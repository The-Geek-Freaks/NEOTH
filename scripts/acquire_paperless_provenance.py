#!/usr/bin/env python3
"""Hosted-only, bounded recursive OCI blob receipt acquisition for Paperless P2-20.

This script hash-verifies selected config and compressed layer bytes by
streaming them without retaining, extracting, installing, or running an image.
Bearer tokens remain in memory and are never written or printed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import ssl
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit


MAX_TOKEN_BYTES = 64 * 1024
MAX_FETCHED_MANIFEST_BYTES = 512 * 1024
MAX_CONFIG_BYTES = 1024 * 1024
MAX_LAYER_BYTES = 512 * 1024 * 1024
MAX_BLOB_BYTES = 2 * 1024 * 1024 * 1024
MAX_DESCRIPTOR_SIZE = 1 << 40
MAX_INDEX_DESCRIPTORS = 256
MAX_LAYERS_PER_MANIFEST = 32
MAX_BLOBS = 96
REQUEST_TIMEOUT_SECONDS = 30
MAX_ELAPSED_SECONDS = 30 * 60
MAX_BLOB_REDIRECTS = 2
# Three token/index/child-manifest sequences take twelve requests. Each unique
# blob may require its original request plus two bounded redirects.
MAX_REQUESTS = 12 + MAX_BLOBS * (MAX_BLOB_REDIRECTS + 1)
SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
MEDIA_TYPES = {
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
}
MANIFEST_MEDIA_TYPES = {
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
}
CONFIG_MEDIA_TYPES = {
    "application/vnd.oci.image.config.v1+json",
    "application/vnd.docker.container.image.v1+json",
}
UPSTREAM_RELEASE = "v3.2.1"
UPSTREAM_COMMIT = "7575d6078227ebdb4cf443f263d53ebc7575aa37"
UPSTREAM_COMPOSE_SHA256 = "85206b8ae6cd74db70998de6479b4c1f7b50c077772a1af2c026c9ecb35b689c"
UPSTREAM_SOURCE_ARCHIVE_SHA256 = "7391e75706d9dafe84dd2235df12c932c0034a4f453725437d07918eee7a35b8"
SELECTORS = (
    ("paperless", "ghcr.io", "paperless-ngx/paperless-ngx", "3.2.1"),
    ("valkey", "registry-1.docker.io", "valkey/valkey", "9-alpine"),
    ("postgres", "registry-1.docker.io", "library/postgres", "18"),
)
APPROVED_BLOB_REDIRECT_HOSTS = {
    "ghcr.io": {
        "ghcr.io",
        "pkg-containers.githubusercontent.com",
        "github-production-container-registry.s3.amazonaws.com",
    },
    "registry-1.docker.io": {
        "registry-1.docker.io",
        "production.cloudflare.docker.com",
        "production.cloudfront.docker.com",
        "docker-images-prod.s3.dualstack.us-east-1.amazonaws.com",
    },
}


class AcquisitionError(RuntimeError):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise AcquisitionError("redirect rejected")


class CaptureRedirect(urllib.request.HTTPRedirectHandler):
    """Return the 3xx response to the bounded blob caller without following it."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def docker_token_url(registry: str, repository: str) -> str:
    if registry == "ghcr.io":
        return f"https://ghcr.io/token?service=ghcr.io&scope=repository:{repository}:pull"
    if registry == "registry-1.docker.io":
        return (
            "https://auth.docker.io/token?service=registry.docker.io"
            f"&scope=repository:{repository}:pull"
        )
    raise AcquisitionError("registry is not allowlisted")


def manifest_url(registry: str, repository: str, reference: str) -> str:
    if (registry, repository) not in {(entry[1], entry[2]) for entry in SELECTORS}:
        raise AcquisitionError("registry/repository is not allowlisted")
    if not SHA256.fullmatch(reference) and (registry, repository, reference) not in {
        (entry[1], entry[2], entry[3]) for entry in SELECTORS
    }:
        raise AcquisitionError("manifest selector is not allowlisted")
    return f"https://{registry}/v2/{repository}/manifests/{reference}"


def blob_url(registry: str, repository: str, digest: str) -> str:
    if not SHA256.fullmatch(digest):
        raise AcquisitionError("blob digest is invalid")
    manifest_url(registry, repository, digest)
    return f"https://{registry}/v2/{repository}/blobs/{digest}"


def approved_blob_redirect(registry: str, location: str) -> str:
    parsed = urlsplit(location)
    try:
        port = parsed.port
    except ValueError as error:
        raise AcquisitionError("blob redirect is not an approved HTTPS upstream") from error
    host = parsed.hostname.lower() if parsed.hostname else None
    if (
        parsed.scheme != "https"
        or not host
        or not host.isascii()
        or not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?", host)
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or port not in (None, 443)
    ):
        raise AcquisitionError("blob redirect is not an approved HTTPS upstream")
    if host not in APPROVED_BLOB_REDIRECT_HOSTS.get(registry, set()):
        raise AcquisitionError(f"blob redirect host rejected: {host}")
    return location


class BoundedClient:
    def __init__(self) -> None:
        context = ssl.create_default_context()
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        self.opener = urllib.request.build_opener(NoRedirect(), urllib.request.HTTPSHandler(context=context))
        self.blob_opener = urllib.request.build_opener(CaptureRedirect(), urllib.request.HTTPSHandler(context=context))
        self.requests = 0
        self.started_monotonic = time.monotonic()
        self.verified_blobs: dict[tuple[str, str, str], dict[str, object]] = {}
        self.verified_blob_bytes = 0

    def _count_request(self) -> None:
        if time.monotonic() - self.started_monotonic > MAX_ELAPSED_SECONDS:
            raise AcquisitionError("acquisition deadline exceeded")
        self.requests += 1
        if self.requests > MAX_REQUESTS:
            raise AcquisitionError("request count exceeded")

    def get(self, url: str, limit: int, headers: dict[str, str] | None = None) -> tuple[bytes, dict[str, str]]:
        self._count_request()
        request = urllib.request.Request(url, headers=headers or {})
        try:
            with self.opener.open(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
                if response.status != 200:
                    raise AcquisitionError("unexpected HTTP status")
                length = response.headers.get("Content-Length")
                if length is not None and (not length.isdigit() or int(length) > limit):
                    raise AcquisitionError("response exceeds byte limit")
                body = response.read(limit + 1)
                if len(body) > limit:
                    raise AcquisitionError("response exceeds byte limit")
                return body, {key.lower(): value for key, value in response.headers.items()}
        except AcquisitionError:
            raise
        except urllib.error.HTTPError as error:
            raise AcquisitionError(
                f"bounded HTTPS request failed: HTTP {error.code}, request {self.requests}"
            ) from None
        except (urllib.error.URLError, TimeoutError):
            raise AcquisitionError(
                f"bounded HTTPS transport failed: request {self.requests}"
            ) from None

    def verified_blob(
        self,
        registry: str,
        repository: str,
        token: str,
        descriptor_value: dict[str, object],
        kind: str,
    ) -> dict[str, object]:
        if set(descriptor_value) == {"digest", "size", "media_type"}:
            digest_value = descriptor_value["digest"]
            size_value = descriptor_value["size"]
            media_type_value = descriptor_value["media_type"]
            if (
                not isinstance(digest_value, str)
                or not SHA256.fullmatch(digest_value)
                or isinstance(size_value, bool)
                or not isinstance(size_value, int)
                or size_value < 0
                or size_value > MAX_DESCRIPTOR_SIZE
                or not isinstance(media_type_value, str)
                or len(media_type_value) > 256
            ):
                raise AcquisitionError("canonical blob descriptor is invalid")
            descriptor_data = {"digest": digest_value, "size": size_value, "media_type": media_type_value}
        else:
            descriptor_data = descriptor(descriptor_value)
        digest = str(descriptor_data["digest"])
        declared_bytes = int(descriptor_data["size"])
        limit = MAX_CONFIG_BYTES if kind == "config" else MAX_LAYER_BYTES
        if kind not in {"config", "layer"} or declared_bytes > limit:
            raise AcquisitionError("blob descriptor exceeds kind byte limit")
        key = (registry, repository, digest)
        prior = self.verified_blobs.get(key)
        if prior is not None:
            if prior["declared_bytes"] != declared_bytes:
                raise AcquisitionError("same blob digest has conflicting declared sizes")
            return {**prior, "kind": kind, "deduplicated": True}
        if len(self.verified_blobs) >= MAX_BLOBS or self.verified_blob_bytes + declared_bytes > MAX_BLOB_BYTES:
            raise AcquisitionError("blob count or aggregate byte limit exceeded")

        url = blob_url(registry, repository, digest)
        headers = {"Authorization": f"Bearer {token}"}
        redirects = 0
        while True:
            self._count_request()
            request = urllib.request.Request(url, headers=headers)
            try:
                response = self.blob_opener.open(request, timeout=REQUEST_TIMEOUT_SECONDS)
            except urllib.error.HTTPError as error:
                if error.code not in {301, 302, 303, 307, 308}:
                    error.close()
                    raise AcquisitionError(f"bounded HTTPS request failed: HTTP {error.code}, request {self.requests}") from None
                if redirects >= MAX_BLOB_REDIRECTS:
                    error.close()
                    raise AcquisitionError("blob redirect limit exceeded")
                try:
                    location = error.headers.get("Location")
                    if not location:
                        raise AcquisitionError("blob redirect has no location")
                    url = approved_blob_redirect(registry, location)
                finally:
                    error.close()
                headers = {}
                redirects += 1
                continue
            except (urllib.error.URLError, TimeoutError):
                raise AcquisitionError(f"bounded HTTPS transport failed: request {self.requests}") from None
            try:
                with response:
                    if response.status != 200:
                        raise AcquisitionError("unexpected blob HTTP status")
                    length = response.headers.get("Content-Length")
                    if length is not None and (not length.isdigit() or int(length) != declared_bytes):
                        raise AcquisitionError("blob Content-Length does not match descriptor")
                    observed_bytes = 0
                    hasher = hashlib.sha256()
                    while True:
                        if time.monotonic() - self.started_monotonic > MAX_ELAPSED_SECONDS:
                            raise AcquisitionError("acquisition deadline exceeded")
                        chunk = response.read(1024 * 1024)
                        if time.monotonic() - self.started_monotonic > MAX_ELAPSED_SECONDS:
                            raise AcquisitionError("acquisition deadline exceeded")
                        if not chunk:
                            break
                        observed_bytes += len(chunk)
                        if observed_bytes > declared_bytes:
                            raise AcquisitionError("blob response exceeds descriptor size")
                        hasher.update(chunk)
                    if observed_bytes != declared_bytes or f"sha256:{hasher.hexdigest()}" != digest:
                        raise AcquisitionError("blob response does not match descriptor digest or size")
                    record = {
                        "kind": kind,
                        "digest": digest,
                        "declared_bytes": declared_bytes,
                        "observed_bytes": observed_bytes,
                        "redirects": redirects,
                        "deduplicated": False,
                    }
                    self.verified_blobs[key] = record
                    self.verified_blob_bytes += observed_bytes
                    return record
            except AcquisitionError:
                raise
            except (urllib.error.URLError, TimeoutError, OSError):
                raise AcquisitionError(f"bounded blob transport failed: request {self.requests}") from None


def parse_token(raw: bytes) -> str:
    try:
        token = json.loads(raw.decode("utf-8"))["token"]
    except (UnicodeDecodeError, ValueError, KeyError, TypeError) as error:
        raise AcquisitionError("token response is invalid") from error
    if not isinstance(token, str) or not token or len(token) > 16 * 1024 or any(ord(c) < 33 or ord(c) > 126 for c in token):
        raise AcquisitionError("token response is invalid")
    return token


def descriptor(value: object, allowed_media_types: set[str] | None = None) -> dict[str, object]:
    if not isinstance(value, dict):
        raise AcquisitionError("descriptor is invalid")
    digest, size, media_type = value.get("digest"), value.get("size"), value.get("mediaType")
    if not isinstance(digest, str) or not SHA256.fullmatch(digest):
        raise AcquisitionError("descriptor digest is invalid")
    if isinstance(size, bool) or not isinstance(size, int) or size < 0 or size > MAX_DESCRIPTOR_SIZE:
        raise AcquisitionError("descriptor size is invalid")
    if not isinstance(media_type, str) or len(media_type) > 256 or (allowed_media_types is not None and media_type not in allowed_media_types):
        raise AcquisitionError("descriptor media type is invalid")
    return {"digest": digest, "size": size, "media_type": media_type}


def acquire_manifest(client: BoundedClient, registry: str, repository: str, reference: str, token: str) -> tuple[dict[str, object], dict[str, str], bytes]:
    body, headers = client.get(
        manifest_url(registry, repository, reference),
        MAX_FETCHED_MANIFEST_BYTES,
        {
            "Accept": ", ".join(sorted(MEDIA_TYPES | MANIFEST_MEDIA_TYPES)),
            "Authorization": f"Bearer {token}",
        },
    )
    digest = headers.get("docker-content-digest")
    if digest != sha256(body):
        raise AcquisitionError("Docker-Content-Digest does not bind response bytes")
    try:
        value = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as error:
        raise AcquisitionError("manifest response is invalid JSON") from error
    if not isinstance(value, dict):
        raise AcquisitionError("manifest response is invalid")
    return value, {"digest": digest, "bytes": str(len(body)), "media_type": headers.get("content-type", "").split(";", 1)[0]}, body


def child_for_platform(index: dict[str, object], os_name: str, architecture: str) -> dict[str, object]:
    if index.get("schemaVersion") != 2 or index.get("mediaType") not in MEDIA_TYPES:
        raise AcquisitionError("selector did not resolve to an OCI index")
    manifests = index.get("manifests")
    if not isinstance(manifests, list) or len(manifests) > MAX_INDEX_DESCRIPTORS:
        raise AcquisitionError("index manifests are invalid")
    matches = []
    for candidate in manifests:
        if not isinstance(candidate, dict):
            continue
        platform = candidate.get("platform")
        if not valid_platform(platform):
            continue
        if platform.get("os") == os_name and platform.get("architecture") == architecture:
            matches.append(descriptor(candidate, MANIFEST_MEDIA_TYPES))
    if len(matches) != 1:
        raise AcquisitionError("expected exactly one platform child descriptor")
    return matches[0]


def valid_platform(platform: object) -> bool:
    if not isinstance(platform, dict) or set(platform) - {"os", "architecture", "variant", "os.version", "os.features", "features"}:
        return False
    for name in ("os", "architecture", "variant", "os.version"):
        value = platform.get(name)
        if name in {"os", "architecture"} and (not isinstance(value, str) or not value or len(value) > 64):
            return False
        if name in platform and name not in {"os", "architecture"} and (not isinstance(value, str) or len(value) > 128):
            return False
    for name in ("os.features", "features"):
        value = platform.get(name)
        if value is not None and (
            not isinstance(value, list)
            or len(value) > 32
            or any(not isinstance(item, str) or not item or len(item) > 128 for item in value)
        ):
            return False
    return True


def child_receipt(client: BoundedClient, registry: str, repository: str, token: str, child: dict[str, object]) -> tuple[dict[str, object], tuple[str, bytes]]:
    raw, observed, body = acquire_manifest(client, registry, repository, str(child["digest"]), token)
    if observed["digest"] != child["digest"] or int(observed["bytes"]) != child["size"]:
        raise AcquisitionError("child manifest response does not match index descriptor")
    if observed["media_type"] != child["media_type"] or raw.get("mediaType") != child["media_type"]:
        raise AcquisitionError("child manifest media type does not match index descriptor")
    if raw.get("schemaVersion") != 2 or raw.get("mediaType") not in MANIFEST_MEDIA_TYPES:
        raise AcquisitionError("platform child is not an OCI image manifest")
    config = descriptor(raw.get("config"), CONFIG_MEDIA_TYPES)
    layers = raw.get("layers")
    if not isinstance(layers, list) or len(layers) > MAX_LAYERS_PER_MANIFEST:
        raise AcquisitionError("child manifest layers are invalid")
    for layer in layers:
        layer_descriptor = descriptor(layer)
        if not layer_descriptor["media_type"].startswith(("application/vnd.oci.image.layer.", "application/vnd.docker.image.rootfs.")):
            raise AcquisitionError("layer descriptor media type is invalid")
    return {
        "descriptor": child,
        "content": observed,
        "config": config,
        "layers": [descriptor(layer) for layer in layers],
    }, (observed["digest"], body)


def acquire_selector(client: BoundedClient, name: str, registry: str, repository: str, selector: str) -> dict[str, object]:
    token_raw, _ = client.get(docker_token_url(registry, repository), MAX_TOKEN_BYTES)
    token = parse_token(token_raw)
    index, content, index_body = acquire_manifest(client, registry, repository, selector, token)
    if index.get("schemaVersion") != 2 or index.get("mediaType") not in MEDIA_TYPES:
        raise AcquisitionError("selector did not resolve to an OCI index")
    if content["media_type"] != index["mediaType"]:
        raise AcquisitionError("index manifest content type does not match body")
    amd64, amd64_raw = child_receipt(client, registry, repository, token, child_for_platform(index, "linux", "amd64"))
    arm64, arm64_raw = child_receipt(client, registry, repository, token, child_for_platform(index, "linux", "arm64"))
    for platform in (amd64, arm64):
        platform["verified_blobs"] = [
            client.verified_blob(registry, repository, token, platform["config"], "config"),
            *[
                client.verified_blob(registry, repository, token, layer, "layer")
                for layer in platform["layers"]
            ],
        ]
    return {
        "name": name,
        "registry": registry,
        "repository": repository,
        "selector": selector,
        "index": content,
        "platforms": {
            "linux/amd64": amd64,
            "linux/arm64": arm64,
        },
        "_raw_manifests": [(content["digest"], index_body), amd64_raw, arm64_raw],
    }


def retain_raw_manifest(output: Path, digest: str, body: bytes) -> str:
    if digest != sha256(body) or not SHA256.fullmatch(digest):
        raise AcquisitionError("raw manifest digest is invalid")
    relative = Path("raw-manifests") / "sha256" / f"{digest.removeprefix('sha256:')}.json"
    path = output / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and path.read_bytes() != body:
        raise AcquisitionError("digest-addressed manifest collision")
    path.write_bytes(body)
    return relative.as_posix()


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--source-head", required=True)
    parser.add_argument("--script-sha256", required=True)
    parser.add_argument("--workflow-sha256", required=True)
    parser.add_argument("--test-sha256", required=True)
    parser.add_argument("--documentation-sha256", required=True)
    args = parser.parse_args(argv)
    if not re.fullmatch(r"[0-9a-f]{40}", args.source_head):
        raise AcquisitionError("source head is invalid")
    if not all(
        re.fullmatch(r"[0-9a-f]{64}", value)
        for value in (args.script_sha256, args.workflow_sha256, args.test_sha256, args.documentation_sha256)
    ):
        raise AcquisitionError("source binding hash is invalid")
    started = int(time.time())
    client = BoundedClient()
    selectors = [acquire_selector(client, *selector) for selector in SELECTORS]
    raw_manifests = [raw for selector in selectors for raw in selector.pop("_raw_manifests")]
    if len(raw_manifests) != 9 or len({digest for digest, _ in raw_manifests}) != 9:
        raise AcquisitionError("expected nine distinct index and platform manifests")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    for selector in selectors:
        selector["index"]["raw_manifest_path"] = retain_raw_manifest(
            args.output.parent,
            selector["index"]["digest"],
            next(body for digest, body in raw_manifests if digest == selector["index"]["digest"]),
        )
        for platform in selector["platforms"].values():
            digest = platform["content"]["digest"]
            platform["content"]["raw_manifest_path"] = retain_raw_manifest(
                args.output.parent,
                digest,
                next(body for candidate, body in raw_manifests if candidate == digest),
            )
    receipt = {
        "schema_version": 2,
        "kind": "paperless-oci-recursive-blob-acquisition",
        "source": {
            "head": args.source_head,
            "script_sha256": args.script_sha256,
            "workflow_sha256": args.workflow_sha256,
            "test_sha256": args.test_sha256,
            "documentation_sha256": args.documentation_sha256,
        },
        "upstream": {
            "release": UPSTREAM_RELEASE,
            "commit": UPSTREAM_COMMIT,
            "compose_sha256": UPSTREAM_COMPOSE_SHA256,
            "source_archive_sha256": UPSTREAM_SOURCE_ARCHIVE_SHA256,
        },
        "selectors": selectors,
        "raw_manifest_count": len(raw_manifests),
        "request_count": client.requests,
        "verified_blob_count": len(client.verified_blobs),
        "verified_blob_bytes": client.verified_blob_bytes,
        "artifact_blob_bytes_verified": True,
        "artifact_verified": False,
        "started_unix": started,
        "completed_unix": int(time.time()),
        "claims": [
            "OCI index, platform manifests, config blobs, and compressed layer bytes were hash-verified",
            "No blob bytes were retained, decompressed, extracted, installed, or run",
            "No container, installation, runtime probe, signature verification, or readiness claim was performed",
            "This receipt is candidate provenance for later review; it does not set artifact_verified",
        ],
    }
    args.output.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except AcquisitionError as error:
        print(f"paperless provenance acquisition failed: {error}", file=sys.stderr)
        raise SystemExit(2)
