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


if __name__ == "__main__":
    unittest.main()
