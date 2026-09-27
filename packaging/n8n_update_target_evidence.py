#!/usr/bin/env python3
"""Capture bounded public evidence for the fixed n8n 2.40.7 update candidate.

This verifier intentionally proves metadata and provenance inputs only.  It
does not pull an image, select a Docker platform, or admit an installer update.
Anonymous registry credentials are kept in memory and are never serialized.
"""

from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

VERSION = "2.40.7"
DIGEST = "sha256:ffeb52485f78b1b06c9a832205853cf75da72a07a514c9a27724df85979d6c34"
SOURCE_REF = "release/2.40.7"
SOURCE_COMMIT = "09b3ce6f9889c889e13cf3747f6f6c68eebdeeb6"
OCI_INDEX_MEDIA_TYPE = "application/vnd.oci.image.index.v1+json"
OCI_MANIFEST_MEDIA_TYPE = "application/vnd.oci.image.manifest.v1+json"
MAX_RESPONSE_BYTES = 64 * 1024
MAX_TOKEN_BYTES = 16 * 1024
TIMEOUT_SECONDS = 10

EXPECTED_CHILDREN = {
    ("linux", "amd64"): "sha256:599d68c7b6fb18b5ac1e7cd013a2e72c886ec1c807b9d436d56e90da32c664ac",
    ("linux", "arm64"): "sha256:7215c2cb5c7093041d094f4e1afb1a4be50486962c590d8df6182031c283b2bb",
}


class VerificationError(RuntimeError):
    """An expected public evidence invariant was not satisfied."""


def sha256_digest(body: bytes) -> str:
    return "sha256:" + hashlib.sha256(body).hexdigest()


def read_limited(response: http.client.HTTPResponse, limit: int) -> bytes:
    body = response.read(limit + 1)
    if len(body) > limit:
        raise VerificationError("response_too_large")
    return body


def https_request(host: str, path: str, headers: dict[str, str] | None = None, limit: int = MAX_RESPONSE_BYTES) -> tuple[int, dict[str, str], bytes]:
    """Make one HTTPS request without following redirects or retaining auth."""
    connection = http.client.HTTPSConnection(host, timeout=TIMEOUT_SECONDS)
    try:
        request_headers = {"User-Agent": "neoth-n8n-update-target-evidence/1", "Accept": "application/json"}
        request_headers.update(headers or {})
        connection.request("GET", path, headers=request_headers)
        response = connection.getresponse()
        values = {key.lower(): value for key, value in response.getheaders()}
        return response.status, values, read_limited(response, limit)
    except (OSError, http.client.HTTPException) as error:
        raise VerificationError("https_request_failed") from error
    finally:
        connection.close()


def public_json(host: str, path: str) -> bytes:
    status, headers, body = https_request(host, path)
    if status != 200 or headers.get("location"):
        raise VerificationError("public_json_request_rejected")
    try:
        value = json.loads(body)
    except json.JSONDecodeError as error:
        raise VerificationError("public_json_invalid") from error
    if not isinstance(value, dict):
        raise VerificationError("public_json_shape_invalid")
    return body


def anonymous_token(host: str, path: str) -> str:
    status, headers, body = https_request(host, path, limit=MAX_TOKEN_BYTES)
    if status != 200 or headers.get("location"):
        raise VerificationError("registry_token_request_rejected")
    try:
        value = json.loads(body)
    except json.JSONDecodeError as error:
        raise VerificationError("registry_token_invalid") from error
    if not isinstance(value, dict):
        raise VerificationError("registry_token_shape_invalid")
    token = value.get("token", value.get("access_token"))
    if not isinstance(token, str) or not 8 <= len(token) <= 8192:
        raise VerificationError("registry_token_missing")
    return token


def require_digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or len(value) != 71 or not value.startswith("sha256:"):
        raise VerificationError(label)
    try:
        int(value[7:], 16)
    except ValueError as error:
        raise VerificationError(label) from error
    return value


def validate_index(body: bytes, content_digest: str | None) -> dict[str, str]:
    """Require raw bytes, header, OCI shape and both expected child descriptors."""
    if sha256_digest(body) != DIGEST:
        raise VerificationError("index_body_digest_mismatch")
    if content_digest != DIGEST:
        raise VerificationError("index_header_digest_mismatch")
    try:
        index = json.loads(body)
    except json.JSONDecodeError as error:
        raise VerificationError("index_json_invalid") from error
    if not isinstance(index, dict) or index.get("schemaVersion") != 2 or index.get("mediaType") != OCI_INDEX_MEDIA_TYPE:
        raise VerificationError("index_shape_invalid")
    manifests = index.get("manifests")
    if not isinstance(manifests, list) or len(manifests) != len(EXPECTED_CHILDREN):
        raise VerificationError("index_manifest_count_invalid")
    actual: dict[tuple[str, str], str] = {}
    for descriptor in manifests:
        if not isinstance(descriptor, dict) or descriptor.get("mediaType") != OCI_MANIFEST_MEDIA_TYPE:
            raise VerificationError("index_descriptor_media_type_invalid")
        platform = descriptor.get("platform")
        if not isinstance(platform, dict):
            raise VerificationError("index_platform_invalid")
        os_name, architecture = platform.get("os"), platform.get("architecture")
        key = (os_name, architecture)
        if not isinstance(os_name, str) or not isinstance(architecture, str) or key in actual:
            raise VerificationError("index_platform_invalid")
        actual[key] = require_digest(descriptor.get("digest"), "index_child_digest_invalid")
    if actual != EXPECTED_CHILDREN:
        raise VerificationError("index_platform_children_mismatch")
    return {f"{os_name}/{architecture}": digest for (os_name, architecture), digest in sorted(actual.items())}


def validate_release(release_body: bytes, tag_ref_body: bytes, annotated_tag_body: bytes | None = None) -> None:
    try:
        release, tag_ref = json.loads(release_body), json.loads(tag_ref_body)
    except json.JSONDecodeError as error:
        raise VerificationError("release_json_invalid") from error
    if not isinstance(release, dict) or not isinstance(tag_ref, dict):
        raise VerificationError("release_shape_invalid")
    if release.get("tag_name") != f"n8n@{VERSION}" or release.get("draft") is not False or release.get("prerelease") is not False:
        raise VerificationError("release_identity_invalid")
    if release.get("target_commitish") != SOURCE_REF:
        raise VerificationError("release_source_ref_invalid")
    obj = tag_ref.get("object")
    if tag_ref.get("ref") != f"refs/tags/n8n@{VERSION}" or not isinstance(obj, dict):
        raise VerificationError("release_tag_commit_invalid")
    if obj.get("type") == "commit" and obj.get("sha") == SOURCE_COMMIT and annotated_tag_body is None:
        return
    if obj.get("type") != "tag" or not isinstance(obj.get("sha"), str) or annotated_tag_body is None:
        raise VerificationError("release_tag_commit_invalid")
    try:
        annotated_tag = json.loads(annotated_tag_body)
    except json.JSONDecodeError as error:
        raise VerificationError("release_tag_object_invalid") from error
    target = annotated_tag.get("object") if isinstance(annotated_tag, dict) else None
    if not isinstance(target, dict) or target.get("type") != "commit" or target.get("sha") != SOURCE_COMMIT:
        raise VerificationError("release_tag_commit_invalid")


def registry_index(name: str, registry_host: str, repository: str, token_host: str, token_path: str) -> tuple[bytes, dict[str, object]]:
    token = anonymous_token(token_host, token_path)
    try:
        status, headers, body = https_request(
            registry_host,
            f"/v2/{repository}/manifests/{DIGEST}",
            {
                "Accept": OCI_INDEX_MEDIA_TYPE,
                "Authorization": f"Bearer {token}",
            },
        )
    finally:
        # Do not retain auth material past the one request.
        token = ""
    if status != 200 or headers.get("location"):
        raise VerificationError(f"{name}_index_request_rejected")
    children = validate_index(body, headers.get("docker-content-digest"))
    observation = {
        "registry": registry_host,
        "repository": repository,
        "request": f"https://{registry_host}/v2/{repository}/manifests/{DIGEST}",
        "status": status,
        "content_type": headers.get("content-type"),
        "docker_content_digest": headers.get("docker-content-digest"),
        "raw_sha256": sha256_digest(body),
        "children": children,
    }
    return body, observation


def write_bytes(path: Path, body: bytes) -> None:
    path.write_bytes(body)


def capture(receipt_dir: Path) -> None:
    receipt_dir.mkdir(parents=True, exist_ok=True)
    release_body = public_json("api.github.com", f"/repos/n8n-io/n8n/releases/tags/n8n%40{VERSION}")
    tag_ref_body = public_json("api.github.com", f"/repos/n8n-io/n8n/git/ref/tags/n8n%40{VERSION}")
    tag_ref = json.loads(tag_ref_body)
    tag_object_body: bytes | None = None
    tag_object = tag_ref.get("object") if isinstance(tag_ref, dict) else None
    if isinstance(tag_object, dict) and tag_object.get("type") == "tag" and isinstance(tag_object.get("sha"), str):
        tag_object_body = public_json("api.github.com", f"/repos/n8n-io/n8n/git/tags/{tag_object['sha']}")
    validate_release(release_body, tag_ref_body, tag_object_body)
    ghcr_body, ghcr = registry_index(
        "ghcr", "ghcr.io", "n8n-io/n8n", "ghcr.io",
        "/token?" + urlencode({"scope": "repository:n8n-io/n8n:pull"}),
    )
    docker_body, docker = registry_index(
        "dockerhub", "registry-1.docker.io", "n8nio/n8n", "auth.docker.io",
        "/token?" + urlencode({"service": "registry.docker.io", "scope": "repository:n8nio/n8n:pull"}),
    )
    if ghcr_body != docker_body:
        raise VerificationError("cross_registry_index_bytes_mismatch")
    write_bytes(receipt_dir / "github-release.json", release_body)
    write_bytes(receipt_dir / "github-tag-ref.json", tag_ref_body)
    if tag_object_body is not None:
        write_bytes(receipt_dir / "github-tag-object.json", tag_object_body)
    write_bytes(receipt_dir / "ghcr-index.json", ghcr_body)
    write_bytes(receipt_dir / "dockerhub-index.json", docker_body)
    (receipt_dir / "registry-observation.json").write_text(json.dumps({"candidate": {"version": VERSION, "digest": DIGEST, "source_ref": SOURCE_REF, "source_commit": SOURCE_COMMIT}, "ghcr": ghcr, "dockerhub": docker, "same_raw_index_bytes": True}, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--receipt-dir", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.receipt_dir is None:
            raise VerificationError("receipt_dir_required")
        capture(args.receipt_dir)
    except VerificationError as error:
        print(str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
