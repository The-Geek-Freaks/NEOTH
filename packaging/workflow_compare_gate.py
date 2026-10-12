#!/usr/bin/env python3
"""Compare retained single-turn skill replays without executing a provider.

This is measurement, not release acceptance, model training or promotion.
The operator retains private corpus/report bytes; only hash-bound counts leave
this tool. A separately retained protocol hash binds the intended comparison.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
from typing import Iterable

_SPEC = importlib.util.spec_from_file_location(
    "workflow_replay_gate", Path(__file__).with_name("workflow_replay_gate.py")
)
assert _SPEC is not None and _SPEC.loader is not None
replay = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(replay)

Error = replay.WorkflowReplayGateError
PROTOCOL_KEYS = {
    "schema_version", "kind", "source_revision", "corpus_sha256",
    "episode_ids", "scorer", "config", "baseline", "candidate", "hard_case_ids",
}
VARIANT_KEYS = {"id", "skill_id", "skill_content_sha256"}
CONTAINMENT = {
    "transient_home": True, "transient_workspace": True,
    "actual_home_effects": ["provider_consent_and_cost_usage_audit"],
    "external_tools": "deny_all",
}


def _ids(value: object, name: str) -> list[str]:
    if not isinstance(value, list) or not 1 <= len(value) <= 64:
        raise Error(f"{name} must contain 1..64 IDs")
    for item in value:
        replay._text(item, name)
    if len(set(value)) != len(value):
        raise Error(f"{name} has duplicate IDs")
    return value


def _config(value: object) -> dict[str, object]:
    config = replay._keys(value, replay.CONFIG_KEYS, "config")
    cap = config["max_per_request"]
    if type(cap) is not int or cap <= 0:
        raise Error("max_per_request must be a positive integer")
    if config["model"] == "provider_default":
        raise Error("comparison requires an explicitly selected model")
    expected = replay._config_fingerprint(config["provider"], config["model"], cap)
    if config["fingerprint_sha256"] != expected:
        raise Error("config fingerprint does not bind provider/model/cap")
    replay._sha256(config["effective_public_config_sha256"], "public config hash")
    return config


def _protocol(
    path: Path, expected_hash: str, source_revision: str
) -> tuple[dict[str, object], str]:
    replay._sha256(expected_hash, "expected protocol hash")
    if not replay.GIT_REVISION.fullmatch(source_revision):
        raise Error("invalid expected source revision")
    raw, data = replay._load_json(path, "protocol")
    digest = hashlib.sha256(data).hexdigest()
    if digest != expected_hash:
        raise Error("protocol bytes differ from the separately retained hash")
    protocol = replay._keys(raw, PROTOCOL_KEYS, "protocol")
    if (
        type(protocol["schema_version"]) is not int
        or protocol["schema_version"] != 1
        or protocol["kind"] != "workflow-replay-comparison-protocol-v1"
    ):
        raise Error("unsupported comparison protocol")
    if protocol["source_revision"] != source_revision:
        raise Error("protocol source revision differs")
    replay._sha256(protocol["corpus_sha256"], "corpus hash")
    ids = _ids(protocol["episode_ids"], "episode_ids")
    hard = _ids(protocol["hard_case_ids"], "hard_case_ids")
    if not set(hard) <= set(ids):
        raise Error("hard cases must be declared corpus IDs")
    if protocol["scorer"] != "contains-v1":
        raise Error("only the existing contains-v1 scorer is supported")
    _config(protocol["config"])
    for role in ("baseline", "candidate"):
        variant = replay._keys(protocol[role], VARIANT_KEYS, role)
        replay._text(variant["id"], "variant ID")
        replay._text(variant["skill_id"], "skill ID")
        replay._sha256(variant["skill_content_sha256"], "skill content hash")
    baseline, candidate = protocol["baseline"], protocol["candidate"]
    if baseline["id"] == candidate["id"]:
        raise Error("variant IDs must differ")
    if baseline["skill_id"] != candidate["skill_id"]:
        raise Error("both variants must force the same skill ID")
    if baseline["skill_content_sha256"] == candidate["skill_content_sha256"]:
        raise Error("skill variants must have different content hashes")
    return protocol, digest


def _report(
    path: Path, protocol: dict[str, object], role: str
) -> tuple[list[dict[str, object]], str, list[int]]:
    raw, data = replay._load_json(path, role)
    report = replay._keys(raw, replay.REPORT_KEYS, role)
    if (
        type(report["schema_version"]) is not int
        or report["schema_version"] != 1
        or report["kind"] != "workflow-replay-report-v1"
    ):
        raise Error("unsupported replay report")
    for field in ("source_revision", "corpus_sha256", "scorer"):
        if report[field] != protocol[field]:
            raise Error(f"{role} {field} differs")
    config = _config(report["config"])
    if config != protocol["config"]:
        raise Error(f"{role} model/config/request cap differs")
    containment = replay._keys(
        report["containment"], replay.CONTAINMENT_KEYS, "containment"
    )
    if (
        containment != CONTAINMENT
        or containment["transient_home"] is not True
        or containment["transient_workspace"] is not True
    ):
        raise Error("replay containment must be transient and deny_all")
    rows = report["episodes"]
    ids = protocol["episode_ids"]
    if not isinstance(rows, list) or len(rows) != len(ids):
        raise Error("report must retain every planned episode")
    variant = protocol[role]
    unbound = []
    for index, raw_row in enumerate(rows):
        row = replay._keys(raw_row, replay.REPORT_EPISODE_KEYS, "episode")
        if row["episode_id"] != ids[index]:
            raise Error("episode identity/order differs from frozen protocol")
        if row["provider"] != config["provider"] or row["model"] != config["model"]:
            raise Error("episode used a different provider/model")
        outcome = row["outcome"]
        if not isinstance(outcome, str) or outcome not in ("pass", "fail", "error"):
            raise Error("invalid episode outcome")
        if outcome == "pass":
            if row["reason"] is not None:
                raise Error("passing episode must not carry a failure reason")
        else:
            replay._text(row["reason"], "failure reason")
        response = row["response_sha256"]
        if response is not None:
            replay._sha256(response, "response hash")
        elif outcome != "error":
            raise Error("pass/fail episode requires a response hash")
        selected = row["selected_skill"]
        selected_hash = row["selected_skill_content_sha256"]
        if selected is None and selected_hash is None and outcome == "error":
            # The real producer loses skill observation on an early error.
            # Keep the failure in the denominator; never infer a skill binding.
            unbound.append(index)
        elif (
            selected != variant["skill_id"]
            or selected_hash != variant["skill_content_sha256"]
        ):
            raise Error("episode skill does not match the declared variant")
    if type(report["passed"]) is not bool or report["passed"] != all(
        row["outcome"] == "pass" for row in rows
    ):
        raise Error("report passed flag disagrees with retained outcomes")
    return rows, hashlib.sha256(data).hexdigest(), unbound


def compare(
    protocol_path: Path, corpus_path: Path, baseline_path: Path,
    candidate_path: Path, expected_protocol_hash: str, source_revision: str,
) -> dict[str, object]:
    protocol, protocol_hash = _protocol(
        protocol_path, expected_protocol_hash, source_revision
    )
    raw, corpus_bytes = replay._load_json(corpus_path, "corpus")
    corpus = replay._keys(raw, replay.CORPUS_KEYS, "corpus")
    skills = replay._corpus_episode_ids(corpus)
    if hashlib.sha256(corpus_bytes).hexdigest() != protocol["corpus_sha256"]:
        raise Error("corpus bytes differ")
    if list(skills) != protocol["episode_ids"]:
        raise Error("corpus identity/order differs")
    if any(skill != protocol["baseline"]["skill_id"] for skill in skills.values()):
        raise Error("all corpus cases must explicitly force the declared skill")
    baseline, baseline_hash, baseline_unbound = _report(
        baseline_path, protocol, "baseline"
    )
    candidate, candidate_hash, candidate_unbound = _report(
        candidate_path, protocol, "candidate"
    )
    def counts(rows: list[dict[str, object]]) -> dict[str, int]:
        return {
            outcome: sum(row["outcome"] == outcome for row in rows)
            for outcome in ("pass", "fail", "error")
        }

    before, after = counts(baseline), counts(candidate)
    regressions = [
        index for index, (a, b) in enumerate(zip(baseline, candidate))
        if a["outcome"] == "pass" and b["outcome"] != "pass"
    ]
    hard = {
        index for index, name in enumerate(protocol["episode_ids"])
        if name in protocol["hard_case_ids"]
    }
    return {
        "schema_version": 1, "kind": "workflow-replay-comparison-witness-v1",
        "source_revision": source_revision, "protocol_sha256": protocol_hash,
        "corpus_sha256": protocol["corpus_sha256"],
        "baseline_report_sha256": baseline_hash,
        "candidate_report_sha256": candidate_hash,
        "episode_count": len(baseline), "baseline": before, "candidate": after,
        "candidate_minus_baseline_passes": after["pass"] - before["pass"],
        "regression_indices": regressions,
        "hard_case_regression_indices": [i for i in regressions if i in hard],
        "candidate_hard_case_failure_indices": sorted(
            i for i in hard if candidate[i]["outcome"] != "pass"
        ),
        "unobserved_variant_indices": {
            "baseline": baseline_unbound, "candidate": candidate_unbound,
        },
        "comparison_complete": not baseline_unbound and not candidate_unbound,
        "inconclusive": bool(baseline_unbound or candidate_unbound),
        "reported_containment_matches_contract": True,
        "historical_preregistration_verified": False,
        "report_authenticity_independently_verified": False,
        "cost_status": "unknown", "token_usage_status": "unknown",
        "provider_attempt_count_status": "unknown",
        "result": "measurement_only", "automatic_promotion": False,
    }


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("protocol", "corpus", "baseline", "candidate", "out"):
        parser.add_argument(f"--{name}", type=Path, required=True)
    parser.add_argument("--expected-protocol-sha256", required=True)
    parser.add_argument("--expected-source-revision", required=True)
    args = parser.parse_args(argv)
    try:
        witness = compare(
            args.protocol, args.corpus, args.baseline, args.candidate,
            args.expected_protocol_sha256, args.expected_source_revision,
        )
        # Exclusive creation refuses overwrite even when another writer races.
        with args.out.open("x", encoding="utf-8", newline="\n") as output:
            output.write(json.dumps(witness, sort_keys=True, indent=2) + "\n")
        print("workflow comparison: measurement written; no promotion authorized")
        return 0
    except (Error, OSError) as error:
        print(f"workflow comparison: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
