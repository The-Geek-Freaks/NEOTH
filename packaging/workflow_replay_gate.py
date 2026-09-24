#!/usr/bin/env python3
"""Validate one explicitly supplied manual workflow-replay release witness.

The release workflow never creates a replay or contacts a provider. An
operator can validate retained local corpus/report bytes, then deliberately
publish only a content-free exact-head witness for optional release checking.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Iterable


SHA256 = re.compile(r"[0-9a-f]{64}\Z")
GIT_REVISION = re.compile(r"[0-9a-f]{40,64}\Z")
MAX_ARTIFACT_BYTES = 2 * 1024 * 1024
CORPUS_KEYS = {"schema_version", "kind", "provenance", "episodes"}
PROVENANCE_KEYS = {"label", "input_sha256"}
CORPUS_EPISODE_KEYS = {"episode_id", "prompt", "expected_contains", "skill"}
REPORT_KEYS = {
    "schema_version", "kind", "corpus_sha256", "source_revision", "scorer",
    "config", "containment", "episodes", "passed",
}
CONFIG_KEYS = {
    "provider", "model", "max_per_request", "fingerprint_sha256",
    "effective_public_config_sha256",
}
CONTAINMENT_KEYS = {
    "transient_home", "transient_workspace", "actual_home_effects", "external_tools",
}
REPORT_EPISODE_KEYS = {
    "episode_id", "outcome", "reason", "provider", "model", "selected_skill",
    "selected_skill_content_sha256", "response_sha256",
}
MANIFEST_KEYS = {
    "schema_version", "kind", "source_revision", "corpus_sha256", "episode_count",
    "episode_ids_sha256", "scorer", "config_fingerprint_sha256",
    "effective_public_config_sha256", "containment", "passed",
}


class WorkflowReplayGateError(ValueError):
    """The supplied manual replay witness cannot authorize this release."""


def _object(value: object, name: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise WorkflowReplayGateError(f"{name} must be a JSON object")
    return value


def _keys(value: object, expected: set[str], name: str) -> dict[str, object]:
    result = _object(value, name)
    if set(result) != expected:
        raise WorkflowReplayGateError(
            f"{name} has unsupported or missing fields: expected {sorted(expected)}, got {sorted(result)}"
        )
    return result


def _keys_with_optional(value: object, required: set[str], optional: set[str], name: str) -> dict[str, object]:
    result = _object(value, name)
    actual = set(result)
    if not required <= actual or not actual <= required | optional:
        raise WorkflowReplayGateError(
            f"{name} has unsupported or missing fields: required {sorted(required)}, optional {sorted(optional)}, got {sorted(result)}"
        )
    return result


def _text(value: object, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise WorkflowReplayGateError(f"{name} must be a nonempty string")
    return value


def _sha256(value: object, name: str) -> str:
    text = _text(value, name)
    if not SHA256.fullmatch(text):
        raise WorkflowReplayGateError(f"{name} must be lowercase SHA-256")
    return text


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise WorkflowReplayGateError(f"JSON object has duplicate key {key!r}")
        result[key] = value
    return result


def _load_json(path: Path, name: str) -> tuple[object, bytes]:
    try:
        with path.open("rb") as source:
            raw = source.read(MAX_ARTIFACT_BYTES + 1)
    except OSError as error:
        raise WorkflowReplayGateError(f"cannot read {name} {path}: {error}") from error
    if len(raw) > MAX_ARTIFACT_BYTES:
        raise WorkflowReplayGateError(f"{name} exceeds {MAX_ARTIFACT_BYTES} byte bound")
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys), raw
    except (UnicodeDecodeError, json.JSONDecodeError, WorkflowReplayGateError) as error:
        raise WorkflowReplayGateError(f"cannot parse {name} {path}: {error}") from error


def _corpus_episode_ids(corpus: dict[str, object]) -> dict[str, object]:
    if (
        type(corpus.get("schema_version")) is not int
        or corpus.get("schema_version") != 1
        or corpus.get("kind") != "workflow-replay-corpus-v1"
    ):
        raise WorkflowReplayGateError("corpus must be workflow-replay-corpus-v1 schema 1")
    provenance = _keys(corpus.get("provenance"), PROVENANCE_KEYS, "corpus.provenance")
    if provenance.get("label") != "operator-curated+inputhash":
        raise WorkflowReplayGateError("corpus provenance must declare operator-curated+inputhash")
    _sha256(provenance.get("input_sha256"), "corpus.provenance.input_sha256")
    episodes = corpus.get("episodes")
    if not isinstance(episodes, list) or not 1 <= len(episodes) <= 64:
        raise WorkflowReplayGateError("corpus must contain 1..64 episodes")
    result: dict[str, object] = {}
    for index, raw in enumerate(episodes):
        episode = _keys_with_optional(
            raw,
            CORPUS_EPISODE_KEYS - {"skill"},
            {"skill"},
            f"corpus.episodes[{index}]",
        )
        episode_id = _text(episode.get("episode_id"), f"corpus.episodes[{index}].episode_id")
        if episode_id in result:
            raise WorkflowReplayGateError(f"corpus has duplicate episode_id {episode_id!r}")
        prompt = _text(episode.get("prompt"), f"corpus.episodes[{index}].prompt")
        _text(episode.get("expected_contains"), f"corpus.episodes[{index}].expected_contains")
        if prompt.lstrip().startswith("/"):
            raise WorkflowReplayGateError(f"corpus episode {episode_id!r} uses a slash-command prompt")
        skill = episode.get("skill")
        if skill is not None:
            _text(skill, f"corpus.episodes[{index}].skill")
        result[episode_id] = skill
    return result


def _episode_ids_sha256(episode_ids: Iterable[str]) -> str:
    canonical = json.dumps(
        sorted(episode_ids), ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def validate(corpus_path: Path, report_path: Path, expected_source_revision: str) -> dict[str, object]:
    """Raise WorkflowReplayGateError unless one supplied report satisfies D5."""

    if not GIT_REVISION.fullmatch(expected_source_revision):
        raise WorkflowReplayGateError("expected source revision must be a lowercase 40..64 character Git revision")
    corpus_raw, corpus_bytes = _load_json(corpus_path, "corpus")
    corpus = _keys(corpus_raw, CORPUS_KEYS, "corpus")
    corpus_skills = _corpus_episode_ids(corpus)
    report_raw, _ = _load_json(report_path, "report")
    report = _keys(report_raw, REPORT_KEYS, "report")
    if (
        type(report.get("schema_version")) is not int
        or report.get("schema_version") != 1
        or report.get("kind") != "workflow-replay-report-v1"
    ):
        raise WorkflowReplayGateError("report must be workflow-replay-report-v1 schema 1")
    if report.get("corpus_sha256") != hashlib.sha256(corpus_bytes).hexdigest():
        raise WorkflowReplayGateError("report corpus_sha256 does not match exact supplied corpus bytes")
    if report.get("source_revision") != expected_source_revision:
        raise WorkflowReplayGateError("report source_revision does not match the exact release candidate")
    if report.get("scorer") != "contains-v1":
        raise WorkflowReplayGateError("report scorer must be contains-v1")
    if report.get("passed") is not True:
        raise WorkflowReplayGateError("report passed must be true")

    config = _keys(report.get("config"), CONFIG_KEYS, "report.config")
    _text(config.get("provider"), "report.config.provider")
    _text(config.get("model"), "report.config.model")
    maximum = config.get("max_per_request")
    if not isinstance(maximum, int) or isinstance(maximum, bool) or maximum <= 0:
        raise WorkflowReplayGateError("report.config.max_per_request must be a positive integer")
    fingerprint = _sha256(config.get("fingerprint_sha256"), "report.config.fingerprint_sha256")
    expected_fingerprint = _config_fingerprint(
        config["provider"], config["model"], maximum
    )
    if fingerprint != expected_fingerprint:
        raise WorkflowReplayGateError("report.config.fingerprint_sha256 does not match the replay config projection")
    public_config_digest = _sha256(
        config.get("effective_public_config_sha256"),
        "report.config.effective_public_config_sha256",
    )

    containment = _keys(report.get("containment"), CONTAINMENT_KEYS, "report.containment")
    if containment.get("transient_home") is not True or containment.get("transient_workspace") is not True:
        raise WorkflowReplayGateError("report containment must use transient home and workspace")
    if containment.get("actual_home_effects") != ["provider_consent_and_cost_usage_audit"]:
        raise WorkflowReplayGateError("report containment actual_home_effects must be exactly provider_consent_and_cost_usage_audit")
    if containment.get("external_tools") != "deny_all":
        raise WorkflowReplayGateError("report containment external_tools must be deny_all")

    episodes = report.get("episodes")
    if not isinstance(episodes, list) or len(episodes) != len(corpus_skills):
        raise WorkflowReplayGateError("report episodes must have the exact corpus episode count")
    observed: set[str] = set()
    for index, raw in enumerate(episodes):
        episode = _keys(raw, REPORT_EPISODE_KEYS, f"report.episodes[{index}]")
        episode_id = _text(episode.get("episode_id"), f"report.episodes[{index}].episode_id")
        if episode_id in observed:
            raise WorkflowReplayGateError(f"report has duplicate episode_id {episode_id!r}")
        if episode_id not in corpus_skills:
            raise WorkflowReplayGateError(f"report has extra episode_id {episode_id!r}")
        observed.add(episode_id)
        if episode.get("outcome") != "pass":
            raise WorkflowReplayGateError(f"report episode {episode_id!r} did not pass")
        if episode.get("reason") is not None:
            raise WorkflowReplayGateError(f"passing report episode {episode_id!r} must not have a reason")
        _text(episode.get("provider"), f"report episode {episode_id!r}.provider")
        _text(episode.get("model"), f"report episode {episode_id!r}.model")
        _sha256(episode.get("response_sha256"), f"report episode {episode_id!r}.response_sha256")
        expected_skill = corpus_skills[episode_id]
        if expected_skill is None:
            selected = episode.get("selected_skill")
            selected_digest = episode.get("selected_skill_content_sha256")
            if (selected is None) != (selected_digest is None):
                raise WorkflowReplayGateError(f"report episode {episode_id!r} has an incoherent auto-routed skill pair")
            if selected is not None:
                _text(selected, f"report episode {episode_id!r}.selected_skill")
                _sha256(selected_digest, f"report episode {episode_id!r}.selected_skill_content_sha256")
        else:
            if episode.get("selected_skill") != expected_skill:
                raise WorkflowReplayGateError(f"report episode {episode_id!r} selected a different skill")
            _sha256(episode.get("selected_skill_content_sha256"), f"report episode {episode_id!r}.selected_skill_content_sha256")
    if observed != set(corpus_skills):
        raise WorkflowReplayGateError("report is missing one or more corpus episode IDs")
    return {
        "schema_version": 1,
        "kind": "workflow-replay-release-witness-v1",
        "source_revision": expected_source_revision,
        "corpus_sha256": hashlib.sha256(corpus_bytes).hexdigest(),
        "episode_count": len(observed),
        "episode_ids_sha256": _episode_ids_sha256(observed),
        "scorer": "contains-v1",
        "config_fingerprint_sha256": fingerprint,
        "effective_public_config_sha256": public_config_digest,
        "containment": containment,
        "passed": True,
    }


def validate_manifest(manifest_path: Path, expected_source_revision: str) -> None:
    if not GIT_REVISION.fullmatch(expected_source_revision):
        raise WorkflowReplayGateError("expected source revision must be a lowercase 40..64 character Git revision")
    raw, _ = _load_json(manifest_path, "release witness manifest")
    manifest = _keys(raw, MANIFEST_KEYS, "release witness manifest")
    if (
        type(manifest.get("schema_version")) is not int
        or manifest.get("schema_version") != 1
        or manifest.get("kind") != "workflow-replay-release-witness-v1"
    ):
        raise WorkflowReplayGateError("release witness manifest must be workflow-replay-release-witness-v1 schema 1")
    if manifest.get("source_revision") != expected_source_revision:
        raise WorkflowReplayGateError("release witness manifest source_revision does not match the exact release candidate")
    _sha256(manifest.get("corpus_sha256"), "release witness manifest corpus_sha256")
    count = manifest.get("episode_count")
    if not isinstance(count, int) or isinstance(count, bool) or not 1 <= count <= 64:
        raise WorkflowReplayGateError("release witness manifest episode_count must be an integer in 1..64")
    _sha256(manifest.get("episode_ids_sha256"), "release witness manifest episode_ids_sha256")
    if manifest.get("scorer") != "contains-v1" or manifest.get("passed") is not True:
        raise WorkflowReplayGateError("release witness manifest must attest a passed contains-v1 replay")
    _sha256(manifest.get("config_fingerprint_sha256"), "release witness manifest config_fingerprint_sha256")
    _sha256(
        manifest.get("effective_public_config_sha256"),
        "release witness manifest effective_public_config_sha256",
    )
    containment = _keys(manifest.get("containment"), CONTAINMENT_KEYS, "release witness manifest.containment")
    if containment.get("transient_home") is not True or containment.get("transient_workspace") is not True:
        raise WorkflowReplayGateError("release witness manifest must use transient home and workspace")
    if containment.get("actual_home_effects") != ["provider_consent_and_cost_usage_audit"]:
        raise WorkflowReplayGateError("release witness manifest actual_home_effects must be exactly provider_consent_and_cost_usage_audit")
    if containment.get("external_tools") != "deny_all":
        raise WorkflowReplayGateError("release witness manifest external_tools must be deny_all")


def _config_fingerprint(provider: object, model: object, maximum: int) -> str:
    """Mirror the versioned Rust producer framing exactly, including NUL bytes."""
    return hashlib.sha256(
        "\0".join(
            [
                "workflow-replay-config-v1",
                _text(provider, "report.config.provider"),
                _text(model, "report.config.model"),
                str(maximum),
                "contains-v1",
                "deny_all",
            ]
        ).encode()
    ).hexdigest()


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--corpus", type=Path)
    result.add_argument("--report", type=Path)
    result.add_argument("--manifest", type=Path)
    result.add_argument("--emit-manifest", type=Path)
    result.add_argument("--expected-source-revision", required=True)
    return result


def main(argv: Iterable[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.manifest is not None:
            if args.corpus is not None or args.report is not None or args.emit_manifest is not None:
                raise WorkflowReplayGateError("--manifest cannot be combined with corpus, report, or emit-manifest")
            validate_manifest(args.manifest, args.expected_source_revision)
            print(f"workflow replay release witness: PASS manifest={args.manifest}")
            return 0
        if args.corpus is None or args.report is None:
            raise WorkflowReplayGateError("--corpus and --report are both required unless --manifest is supplied")
        manifest = validate(args.corpus, args.report, args.expected_source_revision)
        if args.emit_manifest is not None:
            if args.emit_manifest.exists():
                raise WorkflowReplayGateError(f"refusing to overwrite release witness manifest {args.emit_manifest}")
            args.emit_manifest.parent.mkdir(parents=True, exist_ok=True)
            args.emit_manifest.write_text(json.dumps(manifest, sort_keys=True) + "\n", encoding="utf-8")
            print(f"workflow replay release witness: PASS manifest={args.emit_manifest}")
            return 0
    except WorkflowReplayGateError as error:
        print(f"workflow replay release gate: {error}", file=sys.stderr)
        return 1
    print(f"workflow replay release gate: PASS corpus={args.corpus} report={args.report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
