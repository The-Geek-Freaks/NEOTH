#!/usr/bin/env python3
"""Hosted-only, bounded OCI manifest receipt acquisition for Paperless P2-20.

This script intentionally retrieves registry metadata only. It never pulls an
image config or layer, starts no container, and does not claim installation or
runtime readiness. Bearer tokens remain in memory and are never written or
printed.
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


MAX_TOKEN_BYTES = 64 * 1024
MAX_FETCHED_MANIFEST_BYTES = 512 * 1024
MAX_DESCRIPTOR_SIZE = 1 << 40
MAX_INDEX_DESCRIPTORS = 256
REQUEST_TIMEOUT_SECONDS = 15
MAX_REQUESTS = 12
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
    ("paperless", "ghcr.io", "paperless-ngx/paperless-ngx", "v3.2.1"),
    ("valkey", "registry-1.docker.io", "valkey/valkey", "9-alpine"),
    ("postgres", "registry-1.docker.io", "library/postgres", "18"),
)


class AcquisitionError(RuntimeError):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise AcquisitionError("redirect rejected")


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


class BoundedClient:
    def __init__(self) -> None:
        context = ssl.create_default_context()
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        self.opener = urllib.request.build_opener(NoRedirect(), urllib.request.HTTPSHandler(context=context))
        self.requests = 0

    def get(self, url: str, limit: int, headers: dict[str, str] | None = None) -> tuple[bytes, dict[str, str]]:
        self.requests += 1
        if self.requests > MAX_REQUESTS:
            raise AcquisitionError("request count exceeded")
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
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as error:
            raise AcquisitionError("bounded HTTPS request failed") from error


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
    if not isinstance(layers, list) or len(layers) > MAX_INDEX_DESCRIPTORS:
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
    args = parser.parse_args(argv)
    if not re.fullmatch(r"[0-9a-f]{40}", args.source_head):
        raise AcquisitionError("source head is invalid")
    if not all(re.fullmatch(r"[0-9a-f]{64}", value) for value in (args.script_sha256, args.workflow_sha256)):
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
        "schema_version": 1,
        "kind": "paperless-oci-manifest-acquisition",
        "source": {
            "head": args.source_head,
            "script_sha256": args.script_sha256,
            "workflow_sha256": args.workflow_sha256,
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
        "started_unix": started,
        "completed_unix": int(time.time()),
        "claims": [
            "OCI index and platform-manifest metadata only",
            "No config blobs, layers, images, containers, installation, or runtime probe were fetched or run",
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
