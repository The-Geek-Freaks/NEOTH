import importlib.util
import pathlib
import unittest


SCRIPT = pathlib.Path(__file__).with_name("acquire_paperless_provenance.py")
SPEC = importlib.util.spec_from_file_location("paperless_provenance", SCRIPT)
module = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(module)


class PaperlessProvenanceContractTests(unittest.TestCase):
    class FakeClient:
        def __init__(self, responses):
            self.responses = iter(responses)

        def get(self, url, limit, headers=None):
            return next(self.responses)

    class FakeResponse:
        def __init__(self, body, headers):
            self.status = 200
            self.body = body
            self.headers = headers

        def read(self, _limit):
            return self.body

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

    class FakeOpener:
        def __init__(self, response):
            self.response = response

        def open(self, _request, timeout):
            return self.response

    class StreamingResponse:
        def __init__(self, body, headers=None):
            self.status = 200
            self.body = body
            self.offset = 0
            self.headers = headers or {}

        def read(self, limit):
            chunk = self.body[self.offset:self.offset + limit]
            self.offset += len(chunk)
            return chunk

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

    class RecordingBlobOpener:
        def __init__(self, responses):
            self.responses = iter(responses)
            self.requests = []

        def open(self, request, timeout):
            self.requests.append(dict(request.header_items()))
            response = next(self.responses)
            if isinstance(response, Exception):
                raise response
            return response

    def test_only_the_three_inspected_compose_selectors_are_allowlisted(self):
        self.assertEqual(
            module.SELECTORS,
            (
                ("paperless", "ghcr.io", "paperless-ngx/paperless-ngx", "3.2.1"),
                ("valkey", "registry-1.docker.io", "valkey/valkey", "9-alpine"),
                ("postgres", "registry-1.docker.io", "library/postgres", "18"),
            ),
        )
        with self.assertRaises(module.AcquisitionError):
            module.manifest_url("ghcr.io", "paperless-ngx/paperless-ngx", "latest")

    def test_child_manifest_urls_accept_only_sha256_descriptors(self):
        digest = "sha256:" + "a" * 64
        self.assertEqual(
            module.manifest_url("ghcr.io", "paperless-ngx/paperless-ngx", digest),
            f"https://ghcr.io/v2/paperless-ngx/paperless-ngx/manifests/{digest}",
        )
        with self.assertRaises(module.AcquisitionError):
            module.manifest_url("ghcr.io", "paperless-ngx/paperless-ngx", "sha256:not-a-digest")
        with self.assertRaises(module.AcquisitionError):
            module.manifest_url("ghcr.io", "foreign/repository", digest)

    def test_platform_selection_requires_one_exact_child(self):
        digest = "sha256:" + "b" * 64
        index = {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "manifests": [
                {"digest": digest, "size": 123, "mediaType": "application/vnd.oci.image.manifest.v1+json", "platform": {"os": "linux", "architecture": "amd64"}},
                {"digest": "sha256:" + "c" * 64, "size": 124, "mediaType": "application/vnd.oci.image.manifest.v1+json", "platform": {"os": "linux", "architecture": "arm64"}},
            ],
        }
        self.assertEqual(module.child_for_platform(index, "linux", "amd64")["digest"], digest)
        index["manifests"].append(index["manifests"][0])
        with self.assertRaises(module.AcquisitionError):
            module.child_for_platform(index, "linux", "amd64")

    def test_descriptor_rejects_boolean_and_platform_rejects_unbounded_features(self):
        digest = "sha256:" + "d" * 64
        with self.assertRaises(module.AcquisitionError):
            module.descriptor({"digest": digest, "size": True, "mediaType": "application/vnd.oci.image.manifest.v1+json"})
        self.assertFalse(module.valid_platform({"os": "linux", "architecture": "amd64", "features": ["x" * 129]}))

    def test_content_digest_binds_exact_response_bytes(self):
        self.assertEqual(module.sha256(b"manifest"), "sha256:05b3abf2579a5eb66403cd78be557fd860633a1fe2103c7642030defe32c657f")

    def test_manifest_digest_and_bounded_client_reject_tampered_or_oversized_responses(self):
        body = b'{"schemaVersion":2}'
        wrong_digest = "sha256:" + "0" * 64
        with self.assertRaises(module.AcquisitionError):
            module.acquire_manifest(
                self.FakeClient([(body, {"docker-content-digest": wrong_digest, "content-type": "application/vnd.oci.image.index.v1+json"})]),
                "ghcr.io",
                "paperless-ngx/paperless-ngx",
                "3.2.1",
                "unused-token",
            )
        client = module.BoundedClient()
        client.opener = self.FakeOpener(self.FakeResponse(b"four", {"Content-Length": "4"}))
        with self.assertRaises(module.AcquisitionError):
            client.get("https://ghcr.io/token?service=ghcr.io&scope=repository:paperless-ngx/paperless-ngx:pull", 3)
        client.requests = module.MAX_REQUESTS
        with self.assertRaises(module.AcquisitionError):
            client.get("https://ghcr.io/token?service=ghcr.io&scope=repository:paperless-ngx/paperless-ngx:pull", 3)

    def test_http_failure_diagnostic_keeps_only_status_and_request_number(self):
        class FailingOpener:
            def open(self, _request, timeout):
                raise module.urllib.error.HTTPError(
                    "https://ghcr.io/private-query-secret", 404, "sensitive-server-body", {}, None
                )

        client = module.BoundedClient()
        client.opener = FailingOpener()
        with self.assertRaises(module.AcquisitionError) as caught:
            client.get("https://ghcr.io/token", 64)
        self.assertEqual(str(caught.exception), "bounded HTTPS request failed: HTTP 404, request 1")
        self.assertNotIn("secret", str(caught.exception))
        self.assertNotIn("sensitive", str(caught.exception))

    def test_child_receipt_binds_digest_size_media_and_records_large_layer_metadata_without_pull(self):
        digest = "sha256:" + "e" * 64
        child_body = (
            b'{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json",'
            b'"config":{"digest":"sha256:' + b"c" * 64 + b'","size":999999,"mediaType":"application/vnd.oci.image.config.v1+json"},'
            b'"layers":[{"digest":"sha256:' + b"d" * 64 + b'","size":600000,"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip"}]}'
        )
        observed_digest = module.sha256(child_body)
        child = {"digest": observed_digest, "size": len(child_body), "media_type": "application/vnd.oci.image.manifest.v1+json"}
        headers = {"docker-content-digest": observed_digest, "content-type": child["media_type"]}
        receipt, retained = module.child_receipt(
            self.FakeClient([(child_body, headers)]), "ghcr.io", "paperless-ngx/paperless-ngx", "unused-token", child
        )
        self.assertGreater(receipt["layers"][0]["size"], module.MAX_FETCHED_MANIFEST_BYTES)
        self.assertEqual(retained, (observed_digest, child_body))
        for invalid in (
            {**child, "size": len(child_body) + 1},
            {**child, "digest": digest},
            {**child, "media_type": "application/vnd.docker.distribution.manifest.v2+json"},
        ):
            with self.assertRaises(module.AcquisitionError):
                module.child_receipt(
                    self.FakeClient([(child_body, headers)]), "ghcr.io", "paperless-ngx/paperless-ngx", "unused-token", invalid
                )

    def test_blob_stream_requires_exact_descriptor_size_and_digest_without_retention(self):
        body = b"verified-config"
        descriptor = {
            "digest": module.sha256(body),
            "size": len(body),
            "mediaType": "application/vnd.oci.image.config.v1+json",
        }
        client = module.BoundedClient()
        client.blob_opener = self.RecordingBlobOpener([self.StreamingResponse(body, {"Content-Length": str(len(body))})])
        record = client.verified_blob("ghcr.io", "paperless-ngx/paperless-ngx", "token", descriptor, "config")
        self.assertEqual(record["observed_bytes"], len(body))
        self.assertEqual(client.verified_blob_bytes, len(body))
        self.assertEqual(len(client.verified_blobs), 1)

        for wrong_body, wrong_size in ((body[:-1], len(body)), (body + b"x", len(body)), (b"X" * len(body), len(body)), (body, len(body) + 1)):
            client = module.BoundedClient()
            client.blob_opener = self.RecordingBlobOpener([self.StreamingResponse(wrong_body)])
            with self.assertRaises(module.AcquisitionError):
                client.verified_blob(
                    "ghcr.io",
                    "paperless-ngx/paperless-ngx",
                    "token",
                    {**descriptor, "size": wrong_size},
                    "config",
                )

    def test_blob_limits_deduplication_and_redirect_credential_stripping(self):
        body = b"layer"
        descriptor = {
            "digest": module.sha256(body),
            "size": len(body),
            "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
        }
        client = module.BoundedClient()
        opener = self.RecordingBlobOpener([self.StreamingResponse(body)])
        client.blob_opener = opener
        first = client.verified_blob("ghcr.io", "paperless-ngx/paperless-ngx", "token", descriptor, "layer")
        second = client.verified_blob("ghcr.io", "paperless-ngx/paperless-ngx", "token", descriptor, "layer")
        self.assertFalse(first["deduplicated"])
        self.assertTrue(second["deduplicated"])
        self.assertEqual(len(opener.requests), 1)

        over_budget = module.BoundedClient()
        over_budget.verified_blob_bytes = module.MAX_BLOB_BYTES
        with self.assertRaises(module.AcquisitionError):
            over_budget.verified_blob("ghcr.io", "paperless-ngx/paperless-ngx", "token", descriptor, "layer")

        redirect = module.urllib.error.HTTPError(
            "https://ghcr.io/v2/x", 307, "redirect", {"Location": "https://pkg-containers.githubusercontent.com/blob"}, None
        )
        redirected = module.BoundedClient()
        redirect_opener = self.RecordingBlobOpener([redirect, self.StreamingResponse(body)])
        redirected.blob_opener = redirect_opener
        redirected.verified_blob("ghcr.io", "paperless-ngx/paperless-ngx", "token", descriptor, "layer")
        self.assertIn("Authorization", redirect_opener.requests[0])
        self.assertNotIn("Authorization", redirect_opener.requests[1])
        for location in ("http://pkg-containers.githubusercontent.com/blob", "https://token@pkg-containers.githubusercontent.com/blob", "https://127.0.0.1/blob"):
            with self.assertRaises(module.AcquisitionError):
                module.approved_blob_redirect("ghcr.io", location)
        with self.assertRaises(module.AcquisitionError) as caught:
            module.approved_blob_redirect("ghcr.io", "https://unknown.example.invalid/signed/path?token=never-print")
        self.assertEqual(str(caught.exception), "blob redirect host rejected: unknown.example.invalid")
        self.assertNotIn("token", str(caught.exception))
        self.assertNotIn("path", str(caught.exception))

    def test_blob_deadline_after_read_and_redirect_cap_fail_closed(self):
        body = b"late-eof"
        descriptor = {"digest": module.sha256(body), "size": len(body), "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip"}
        original_monotonic = module.time.monotonic
        # Init, request admission, body read before/after, then EOF before/after.
        # Only the final empty read crosses the deadline.
        ticks = iter((0, 0, 0, 0, 0, module.MAX_ELAPSED_SECONDS + 1))
        try:
            module.time.monotonic = lambda: next(ticks)
            client = module.BoundedClient()
            client.blob_opener = self.RecordingBlobOpener([self.StreamingResponse(body)])
            with self.assertRaises(module.AcquisitionError) as caught:
                client.verified_blob("ghcr.io", "paperless-ngx/paperless-ngx", "token", descriptor, "layer")
            self.assertEqual(str(caught.exception), "acquisition deadline exceeded")
        finally:
            module.time.monotonic = original_monotonic

        redirect = module.urllib.error.HTTPError(
            "https://ghcr.io/v2/x", 307, "redirect", {"Location": "https://pkg-containers.githubusercontent.com/blob"}, None
        )
        client = module.BoundedClient()
        opener = self.RecordingBlobOpener([redirect, redirect, redirect])
        client.blob_opener = opener
        with self.assertRaises(module.AcquisitionError) as caught:
            client.verified_blob("ghcr.io", "paperless-ngx/paperless-ngx", "token", descriptor, "layer")
        self.assertEqual(str(caught.exception), "blob redirect limit exceeded")
        self.assertEqual(len(opener.requests), module.MAX_BLOB_REDIRECTS + 1)

    def test_request_ceiling_covers_each_blob_with_two_redirects(self):
        self.assertEqual(module.MAX_REQUESTS, 12 + module.MAX_BLOBS * (module.MAX_BLOB_REDIRECTS + 1))
        self.assertEqual(module.MAX_REQUESTS, 300)
        client = module.BoundedClient()
        client.requests = module.MAX_REQUESTS - 1
        client._count_request()
        self.assertEqual(client.requests, module.MAX_REQUESTS)
        with self.assertRaises(module.AcquisitionError):
            client._count_request()

    def test_selector_path_passes_child_receipt_canonical_descriptors_to_blob_verifier(self):
        config_amd64, layer_amd64 = b"config-amd64", b"layer-amd64"
        config_arm64, layer_arm64 = b"config-arm64", b"layer-arm64"

        def child(config, layer):
            raw = module.json.dumps({
                "schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "config": {"digest": module.sha256(config), "size": len(config), "mediaType": "application/vnd.oci.image.config.v1+json"},
                "layers": [{"digest": module.sha256(layer), "size": len(layer), "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip"}],
            }, separators=(",", ":")).encode()
            return raw

        amd64_body, arm64_body = child(config_amd64, layer_amd64), child(config_arm64, layer_arm64)
        index_body = module.json.dumps({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "manifests": [
                {"digest": module.sha256(amd64_body), "size": len(amd64_body), "mediaType": "application/vnd.oci.image.manifest.v1+json", "platform": {"os": "linux", "architecture": "amd64"}},
                {"digest": module.sha256(arm64_body), "size": len(arm64_body), "mediaType": "application/vnd.oci.image.manifest.v1+json", "platform": {"os": "linux", "architecture": "arm64"}},
            ],
        }, separators=(",", ":")).encode()

        def manifest_response(body, media_type):
            return body, {"docker-content-digest": module.sha256(body), "content-type": media_type}

        client = module.BoundedClient()
        responses = iter([
            (b'{"token":"token"}', {}),
            manifest_response(index_body, "application/vnd.oci.image.index.v1+json"),
            manifest_response(amd64_body, "application/vnd.oci.image.manifest.v1+json"),
            manifest_response(arm64_body, "application/vnd.oci.image.manifest.v1+json"),
        ])
        client.get = lambda _url, _limit, headers=None: next(responses)
        client.blob_opener = self.RecordingBlobOpener([
            self.StreamingResponse(config_amd64), self.StreamingResponse(layer_amd64),
            self.StreamingResponse(config_arm64), self.StreamingResponse(layer_arm64),
        ])
        selector = module.acquire_selector(client, "paperless", "ghcr.io", "paperless-ngx/paperless-ngx", "3.2.1")
        self.assertEqual(client.verified_blob_bytes, len(config_amd64) + len(layer_amd64) + len(config_arm64) + len(layer_arm64))
        self.assertEqual(len(selector["platforms"]["linux/amd64"]["verified_blobs"]), 2)
        self.assertEqual(len(selector["platforms"]["linux/arm64"]["verified_blobs"]), 2)


if __name__ == "__main__":
    unittest.main()
