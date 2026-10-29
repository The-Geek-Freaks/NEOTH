"""Verify the exact Candle ZIP/Russh pin revision on hosted runners only."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile

_ALLOWED = {
    "SRC/neothd/Cargo.toml": [
        ('"=9.0.0"', '"=9.0.5"'),
        ('"=0.63.2"', '"=0.64.1"'),
    ],
    "SRC/vendor/candle-core/Cargo.toml": [('"=9.0.0"', '"=9.0.5"')],
    "SRC/vendor/candle-core/Cargo.toml.orig": [('"=9.0.0"', '"=9.0.5"')],
}
_SPEC = "packaging/vendor-provenance/candle-core-0.8.4-zip9.json"
_REVISION = "packaging/vendor-provenance/candle-core-0.8.4-pin-revision.json"
_PATCH = "packaging/vendor-provenance/zip9.0.5-russh0.64.1.patch"


def _require(condition, message):
    if not condition:
        raise ValueError(message)


def _digest(data):
    return hashlib.sha256(data).hexdigest()


def _sha(value):
    _require(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value),
             "invalid revision SHA-256")
    return value


def _read(root, relative):
    path = Path(root)
    _require(path.is_dir() and not path.is_symlink(), "invalid custody root")
    for component in Path(relative).parts:
        path /= component
        _require(not path.is_symlink(), f"linked custody input: {relative}")
    _require(path.is_file() and path.stat().st_size <= 16 * 1024 * 1024,
             f"missing or oversized custody input: {relative}")
    return path.read_bytes()


def _object(pairs):
    result = {}
    for key, value in pairs:
        _require(key not in result, f"duplicate JSON field: {key}")
        result[key] = value
    return result


def revision_sources(root: Path, spec: dict) -> dict[str, bytes]:
    """Return original postimages after proving this one exact pin-only revision.

    The caller must retain all original archive, vendor-inventory and source
    checks, substituting these bytes only at the three returned paths.
    """
    revision = json.loads(_read(root, _REVISION), object_pairs_hook=_object)
    _require(isinstance(revision, dict)
             and set(revision) == {"schema", "original", "patchSha256", "changes"},
             "unexpected revision fields")
    _require(revision["schema"] == "neoth.candle-zip-russh-pin-revision.v1",
             "revision schema")
    original = revision["original"]
    _require(isinstance(original, dict) and set(original) == {
        "specPath", "specSha256", "archiveSha256", "patchSha256"
    }, "unexpected original binding fields")
    _require(original["specPath"] == _SPEC, "original spec path")
    spec_bytes = _read(root, _SPEC)
    _require(_digest(spec_bytes) == _sha(original["specSha256"])
             and json.loads(spec_bytes, object_pairs_hook=_object) == spec,
             "original spec differs")
    for relative, key in (
        ("packaging/vendor-provenance/candle-core-0.8.4.crate", "archiveSha256"),
        ("packaging/vendor-provenance/candle-core-0.8.4-zip9.patch", "patchSha256"),
    ):
        _require(original[key] == spec[key], "original custody binding differs")
        _require(_digest(_read(root, relative)) == _sha(original[key]),
                 f"original custody bytes differ: {relative}")
    patch = _read(root, _PATCH)
    _require(_digest(patch) == _sha(revision["patchSha256"]), "revision patch digest")
    # This revision permits only text substitutions, with no filesystem mode,
    # move, copy, deletion, binary payload, or creation operation.
    _require(re.search(rb"(?m)^(?:old mode |new mode |new file mode |deleted file mode |"
                       rb"rename from |rename to |copy from |copy to |"
                       rb"GIT binary patch|Binary files )", patch) is None,
             "non-text pin patch operation")
    for line in patch.splitlines():
        if line.startswith(b"index "):
            _require(re.fullmatch(rb"index [0-9a-f]{40}\.\.[0-9a-f]{40} 100644", line),
                     "unexpected patch file mode")

    baseline = {item["path"]: item for item in spec["changes"]}
    _require(len(baseline) == len(spec["changes"]) == 7, "original change inventory")
    changes = revision["changes"]
    _require(isinstance(changes, list) and len(changes) == 3, "revision change count")
    predecessors, effective = {}, {}
    for change in changes:
        _require(isinstance(change, dict) and set(change) == {
            "path", "before", "after", "edits"
        }, "revision change fields")
        path = change["path"]
        _require(isinstance(path, str) and path in _ALLOWED
                 and path not in predecessors, "revision path escape or duplicate")
        _require(change["edits"] == [
            {"before": old, "after": new} for old, new in _ALLOWED[path]
        ], "revision edits differ")
        _require(_sha(change["before"]) == baseline[path]["after"],
                 "revision predecessor is not the original postimage")
        current = _read(root, path)
        _require(_digest(current) == _sha(change["after"]), "effective source digest")
        previous = current
        for old, new in _ALLOWED[path]:
            old, new = old.encode("ascii"), new.encode("ascii")
            _require(previous.count(new) == 1 and previous.count(old) == 0,
                     "ambiguous inverse pin substitution")
            previous = previous.replace(new, old, 1)
        _require(_digest(previous) == change["before"], "reconstructed source digest")
        predecessors[path], effective[path] = previous, current
    _require(set(predecessors) == set(_ALLOWED), "missing revision path")

    with tempfile.TemporaryDirectory(prefix="neoth-pin-custody-") as directory:
        temporary = Path(directory)
        for path, data in predecessors.items():
            destination = temporary / path
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(data)
        result = subprocess.run(
            ["git", "apply", "--numstat", "-"], cwd=temporary, input=patch,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15, check=True,
        )
        counts = {}
        for line in result.stdout.decode("utf-8").splitlines():
            parts = line.split("\t")
            _require(len(parts) == 3 and parts[0].isdigit() and parts[1].isdigit(),
                     "invalid revision patch numstat")
            added, removed, path = parts
            _require(path in _ALLOWED and path not in counts, "patch path escape")
            counts[path] = (int(added), int(removed))
        _require(counts == {
            path: (len(edits), len(edits)) for path, edits in _ALLOWED.items()
        }, "patch path or line-count mismatch")
        subprocess.run(
            ["git", "apply", "-"], cwd=temporary, input=patch,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15, check=True,
        )
        actual = set()
        for path in temporary.rglob("*"):
            _require(not path.is_symlink(), "patch created link")
            if path.is_dir():
                continue
            _require(path.is_file() and path.stat().st_mode & 0o111 == 0,
                     "patch created nonregular or executable input")
            actual.add(path.relative_to(temporary).as_posix())
        _require(actual == set(_ALLOWED), "patch output inventory mismatch")
        for path in _ALLOWED:
            _require(_read(temporary, path) == effective[path], "patch output differs")
    return predecessors
