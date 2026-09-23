#!/usr/bin/env python3
"""Source-bound receipt generator for the focused W404 citation acceptance lane."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
from typing import Any

# Frozen W155 source-only set, copied as explicit identities because the
# historical work/ inventory is intentionally not committed. The three
# citation_cli_contract entries are the real binary integration harness.
HISTORICAL_TESTS = (
    "tools::citation_lookup::tests::doi_canonicalization_rejects_arbitrary_urls_and_has_fixed_endpoints",
    "tools::citation_lookup::tests::record_fingerprint_and_binding_are_claim_and_identity_bound",
    "tools::citation_lookup::tests::record_bounds_and_serialized_invariant_tampering_are_rejected",
    "tools::citation_lookup::tests::cache_rebinds_current_claim_and_is_offline_safe_hit_or_miss",
    "tools::citation_lookup::tests::cache_rejects_corrupt_future_and_fingerprint_mismatch_entries",
    "tools::citation_lookup::tests::cache_capacity_and_atomic_replacement_keep_only_valid_bounded_entries",
    "tools::citation_lookup::tests::query_aware_live_constructor_rejects_record_reassociation",
    "tools::citation_lookup::tests::cache_touch_cannot_silently_exceed_its_byte_cap",
    "tools::citation_lookup::tests::cache_rejects_fixed_name_final_symlink_without_following_it",
    "tools::citation_consent::tests::store_create_consume_and_replay_are_one_shot",
    "tools::citation_consent::tests::mismatch_and_expiry_fail_before_consumption",
    "tools::citation_consent::tests::deny_consumes_exact_challenge_without_proof",
    "tools::citation_consent::tests::config_generation_invalidation_fails_closed",
    "tools::citation_consent::tests::private_store_rejects_redirected_or_non_private_namespace",
    "tools::citation_http::tests::fixed_endpoints_and_surfaces_are_provider_specific",
    "tools::citation_http::tests::cache_hit_and_offline_miss_never_construct_an_authorizer",
    "tools::citation_http::tests::gui_cache_and_offline_paths_never_mint_or_consume_a_proof",
    "tools::citation_http::tests::gui_live_miss_capability_is_bound_to_its_exact_lookup",
    "tools::citation_http::tests::real_authorized_request_builds_a_canonical_live_record",
    "tools::citation_http::tests::provider_response_mappings_are_identity_bound",
    "tools::citation_http::tests::malformed_or_mismatched_provider_json_is_closed_unavailable",
    "tools::citation_http::tests::timeout_maps_to_a_typed_outcome_through_the_authorized_client_path",
    "tools::citation_http::tests::redirect_is_not_followed_and_returns_closed_unavailable",
    "tools::citation_http::tests::valid_429_sets_only_its_provider_cooldown_without_egress",
    "tools::citation_http::tests::invalid_or_missing_retry_after_does_not_install_a_cooldown",
    "tools::citation_http::tests::cooldown_is_scoped_to_one_provider",
    "tools::citation_http::tests::denied_authorizer_never_enters_the_transport_closure",
    "tools::citation_http::tests::retry_after_parser_is_bounded_and_data_free",
    "tools::citation_http::tests::provider_response_text_never_enters_the_typed_outcome",
    "cli::citation::tests::provider_omission_order_and_explicit_limit_are_pinned",
    "cli::citation::tests::invalid_claim_and_query_reject_before_lookup",
    "cli::citation::tests::clap_binds_explicit_provider_and_offline_without_a_network_path",
    "cli::citation::tests::injected_empty_cache_offline_is_a_typed_miss_without_live_lookup",
    "cli::citation::tests::unavailable_receipt_has_no_display_projection",
    "cli::citation::tests::altered_claim_cannot_render_a_found_display",
    "cli::citation::tests::runner_preserves_order_and_all_prior_typed_outcomes",
    "cli::citation::tests::runner_offline_and_invalid_inputs_construct_zero_authorizers",
    "cli::citation::tests::permission_denied_stops_fallback_and_query_drift_is_rejected",
    "citation_cli_contract::ordinary_and_gui_offline_lookups_emit_typed_receipts_before_nonzero_without_authorizer_wal",
    "citation_cli_contract::gui_lookup_rejects_invalid_input_before_private_proof_or_authorizer",
    "citation_cli_contract::gui_decide_rejects_oversized_private_stdin_before_consent_mutation",
    "tools::external_http::tests::gui_ready_rechecks_current_policy_and_keeps_normal_http_lifecycle",
    "tools::external_http::tests::required_http_decision_failure_blocks_intent_and_transport",
    "tools::external_http::tests::intent_failure_prevents_network",
    "tools::external_http::tests::success_and_failure_close_the_same_request_binding",
    "tools::external_http::tests::permit_is_bound_to_exact_url_and_body",
    "tools::external_http::tests::permit_rejects_a_provenance_binding_mismatch",
    "tools::external_http::tests::terminal_result_audit_failure_is_returned_after_transport",
    "tools::external_http::tests::request_drift_cannot_reach_transport",
)
CANONICAL_SOURCE_PATHS = {
    "SRC/neothd/src/tools/citation_lookup.rs",
    "SRC/neothd/src/tools/citation_consent.rs",
    "SRC/neothd/src/tools/citation_http.rs",
    "SRC/neothd/src/tools/external_http.rs",
    "SRC/neothd/src/cli/citation.rs",
    "SRC/neothd/tests/citation_cli_contract.rs",
}
CURRENT_CACHE_TEST = "tools::citation_lookup::tests::missing_cache_namespace_is_a_read_only_offline_miss"
LIVE_PROBES = (
    ("crossref", "10.1038/nature12373", "W404 public Crossref DOI acceptance"),
    ("openalex", "10.1038/nature12373", "W404 public OpenAlex DOI acceptance"),
    ("semantic-scholar", "10.1038/nature12373", "W404 public Semantic Scholar DOI acceptance"),
)
UNAVAILABLE_KINDS = {"timeout", "rate_limited", "provider_unavailable", "not_found", "permission_denied", "invalid_query", "offline_cache_miss"}


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def run(command: list[str], cwd: Path, log: Path, timeout_secs: int, env: dict[str, str] | None = None) -> tuple[subprocess.CompletedProcess[str], bool]:
    timed_out = False
    try:
        completed = subprocess.run(
            command,
            cwd=cwd,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
            timeout=timeout_secs,
        )
    except subprocess.TimeoutExpired as error:
        partial = error.stdout or ""
        if isinstance(partial, bytes):
            partial = partial.decode("utf-8", errors="replace")
        completed = subprocess.CompletedProcess(command, 124, partial)
        timed_out = True
    log.parent.mkdir(parents=True, exist_ok=True)
    suffix = f"\nW404 runner timeout after {timeout_secs}s; partial output retained.\n" if timed_out else ""
    log.write_text(completed.stdout + suffix, encoding="utf-8", errors="replace")
    return completed, timed_out

def git_head(root: Path) -> str:
    return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()


def load_selection() -> tuple[list[dict[str, str]], set[str]]:
    if len(HISTORICAL_TESTS) != 49 or len(set(HISTORICAL_TESTS)) != 49:
        raise RuntimeError("frozen W155 selection must contain 49 unique identities")
    if CURRENT_CACHE_TEST in HISTORICAL_TESTS:
        raise RuntimeError("current cache-boundary test must be additive to the W155 selection")
    selected = []
    for name in HISTORICAL_TESTS:
        harness = "neoth::citation_cli_contract" if name.startswith("citation_cli_contract::") else "neoth"
        selected.append({"name": name, "harness": harness})
    selected.append({"name": CURRENT_CACHE_TEST, "harness": "neoth"})
    if len(selected) != 50:
        raise RuntimeError("W404 exact native selection must contain 50 identities")
    return selected, set(CANONICAL_SOURCE_PATHS)

def bind_source(root: Path, evidence: Path, expected_head: str) -> list[dict[str, str]]:
    actual_head = git_head(root)
    if actual_head != expected_head:
        raise RuntimeError(f"checked-out source head {actual_head} does not equal dispatch head {expected_head}")
    selection, source_paths = load_selection()
    source_paths.update({

        "SRC/Cargo.lock",
        ".github/workflows/citation-acceptance.yml",
        "packaging/tests/citation_acceptance.py",
    })
    bindings = []
    for relative in sorted(source_paths):
        path = root / relative
        if not path.is_file():
            raise RuntimeError(f"required W404 source input is missing: {relative}")
        bindings.append({"path": relative, "bytes": path.stat().st_size, "sha256": sha256(path)})
    write_json(evidence / "source" / "selection.json", {
        "schema": "neoth-w404-citation-selection/v1",
        "sourceHead": actual_head,
        "selectionSource": "frozen W155 identities embedded in this committed runner",
        "historicalInventoryCount": 49,
        "currentAdditiveTest": CURRENT_CACHE_TEST,
        "selectedCount": len(selection),
        "tests": selection,
    })
    write_json(evidence / "source" / "bindings.json", {
        "schema": "neoth-w404-citation-source-bindings/v1",
        "sourceHead": actual_head,
        "bindings": bindings,
    })
    (evidence / "receipt" / "source-head.txt").parent.mkdir(parents=True, exist_ok=True)
    (evidence / "receipt" / "source-head.txt").write_text(actual_head + "\n", encoding="utf-8")
    return selection


def native(args: argparse.Namespace) -> int:
    root, evidence = Path(args.repository).resolve(), Path(args.evidence_dir).resolve()
    src = root / "SRC"
    selected = bind_source(root, evidence, args.expected_head)
    results: list[dict[str, Any]] = []
    seen_harnesses: set[str] = set()
    for index, item in enumerate(selected, start=1):
        name, harness = item["name"], item["harness"]
        cargo_filter = name.rsplit("::", 1)[-1] if harness == "neoth::citation_cli_contract" else name
        base = ["cargo", "test", "-p", "neoth", "--locked"]
        if harness == "neoth":
            base += ["--lib"]
        elif harness == "neoth::citation_cli_contract":
            base += ["--test", "citation_cli_contract"]
        else:
            raise RuntimeError(f"unsupported citation harness: {harness}")
        timeout_secs = 1500 if harness not in seen_harnesses else 300
        seen_harnesses.add(harness)
        discovery, discovery_timed_out = run(
            base + [cargo_filter, "--", "--exact", "--list"],
            src,
            evidence / "logs" / f"{index:02d}-discovery.log",
            timeout_secs,
        )
        discovered = (
            discovery.returncode == 0
            and not discovery_timed_out
            and len(re.findall(rf"(?m)^{re.escape(cargo_filter)}: test$", discovery.stdout)) == 1
        )
        execution_exit: int | None = None
        execution_timed_out = False
        passed = False
        if discovered:
            execution, execution_timed_out = run(
                base + [cargo_filter, "--", "--exact", "--test-threads=1"],
                src,
                evidence / "logs" / f"{index:02d}-execution.log",
                timeout_secs,
            )
            execution_exit = execution.returncode
            exact_terminal = re.findall(rf"(?m)^test {re.escape(cargo_filter)} \.\.\. ok$", execution.stdout)
            one_pass_summary = len(re.findall(r"(?m)^test result: ok\. 1 passed; 0 failed;", execution.stdout)) == 1
            passed = execution.returncode == 0 and not execution_timed_out and len(exact_terminal) == 1 and one_pass_summary
        results.append({
            "name": name,
            "cargoFilter": cargo_filter,
            "harness": harness,
            "timeoutSecs": timeout_secs,
            "discoveryExit": discovery.returncode,
            "discoveryTimedOut": discovery_timed_out,
            "discoveredExactlyOnce": discovered,
            "executionExit": execution_exit,
            "executionTimedOut": execution_timed_out,
            "passedExactSelectedTerminal": passed,
        })
        if not discovered or not passed:
            break
    completed = len(results)
    not_started = [item["name"] for item in selected[completed:]]
    failed = [item["name"] for item in results if not item["discoveredExactlyOnce"] or not item["passedExactSelectedTerminal"]]
    summary = {
        "schema": "neoth-w404-citation-native-result/v2",
        "expectedCount": 50,
        "discoveredCount": sum(item["discoveredExactlyOnce"] for item in results),
        "executedCount": sum(item["executionExit"] is not None for item in results),
        "passedCount": sum(item["passedExactSelectedTerminal"] for item in results),
        "failed": failed,
        "unstarted": not_started,
        "terminals": results,
    }
    write_json(evidence / "receipt" / "native-result.json", summary)
    return 0 if completed == 50 and not failed else 1

def parse_receipt(stdout: str) -> dict[str, Any]:
    # `--output json` deliberately emits pretty JSON. A typed unavailable
    # result then exits non-zero and may append a diagnostic after that object,
    # so decode the first complete object rather than treating its exit code as
    # absence of a receipt.
    decoder = json.JSONDecoder()
    for match in re.finditer(r"\{", stdout):
        try:
            value, _ = decoder.raw_decode(stdout[match.start():])
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict) and {"claim", "providers", "result", "attempts"}.issubset(value):
            return value
    raise RuntimeError("CLI emitted no machine-readable citation receipt")


def digest_hex(parts: list[bytes]) -> str:
    digest = hashlib.sha256()
    for part in parts:
        digest.update(len(part).to_bytes(8, "little"))
        digest.update(part)
    return digest.hexdigest()


def append_field(target: bytearray, value: str) -> None:
    encoded = value.encode("utf-8")
    target.extend(len(encoded).to_bytes(8, "little"))
    target.extend(encoded)


def verify_found_claim_binding(record: dict[str, Any], binding: dict[str, Any], claim: str, provider: str, doi: str) -> None:
    if record.get("schema_version") != 1 or binding.get("schema_version") != 1:
        raise RuntimeError("found receipt has an unsupported citation schema version")
    if record.get("provider") != provider or record.get("canonical_doi") != doi:
        raise RuntimeError("found receipt record does not match its provider/DOI query")
    record_id, title, authors, year, venue = (record.get("provider_record_id"), record.get("title"), record.get("authors"), record.get("year"), record.get("venue"))
    if not isinstance(record_id, str) or not isinstance(title, str) or not isinstance(authors, list) or not all(isinstance(author, str) for author in authors) or (year is not None and not isinstance(year, int)) or (venue is not None and not isinstance(venue, str)):
        raise RuntimeError("found receipt has malformed record fields for claim binding")
    record_fields = bytearray()
    for value in ("1", provider, record_id, doi, title, *authors, "" if year is None else str(year), "" if venue is None else venue):
        append_field(record_fields, value)
    record_fingerprint = digest_hex([b"neoth.citation.record-fingerprint.v1\0", bytes(record_fields)])
    claim_sha256 = digest_hex([b"neoth.citation.claim.v1\0", claim.encode("utf-8")])
    binding_sha256 = digest_hex([
        b"neoth.citation.binding.v1\0",
        (1).to_bytes(2, "little"),
        claim_sha256.encode("ascii"),
        record_fingerprint.encode("ascii"),
        provider.encode("ascii"),
        record_id.encode("utf-8"),
    ])
    expected = {
        "claim_sha256": claim_sha256,
        "record_fingerprint_sha256": record_fingerprint,
        "provider": provider,
        "provider_record_id": record_id,
        "binding_sha256": binding_sha256,
    }
    if any(binding.get(key) != value for key, value in expected.items()):
        raise RuntimeError("found receipt claim/record binding does not match the Rust contract")


def validate_live_receipt(receipt: dict[str, Any], provider: str, doi: str, claim: str) -> tuple[bool, str]:
    attempts = receipt.get("attempts")
    if receipt.get("claim") != claim or not isinstance(attempts, list) or len(attempts) != 1:
        raise RuntimeError("citation receipt does not bind exactly one expected claim/attempt")
    attempt = attempts[0]
    if attempt.get("provider") != provider or attempt.get("doi") != doi:
        raise RuntimeError("citation receipt provider or canonical DOI does not match the dispatched query")
    result = attempt.get("result")
    if result != receipt.get("result") or not isinstance(result, dict):
        raise RuntimeError("citation receipt has an inconsistent terminal result")
    status = result.get("status")
    if status == "found":
        record, binding = result.get("record"), result.get("binding")
        provenance = record.get("provenance") if isinstance(record, dict) else None
        if not isinstance(record, dict) or not isinstance(binding, dict) or result.get("source") != "live" or not isinstance(provenance, dict) or provenance.get("provider") != provider or provenance.get("source") != "live":
            raise RuntimeError("found receipt is not a provider-bound live record")
        verify_found_claim_binding(record, binding, claim, provider, doi)
        return True, "found_live"
    if status == "unavailable":
        state = result.get("state")
        if result.get("provider") != provider or not isinstance(state, dict) or state.get("kind") not in UNAVAILABLE_KINDS:
            raise RuntimeError("unavailable receipt is not a typed provider terminal")
        return False, f"unavailable:{state['kind']}"
    raise RuntimeError("citation receipt has an unknown terminal status")

def live(args: argparse.Namespace) -> int:
    root, evidence = Path(args.repository).resolve(), Path(args.evidence_dir).resolve()
    bind_source(root, evidence, args.expected_head)
    cli = Path(args.cli_bin).resolve()
    if not cli.is_file() or not os.access(cli, os.X_OK):
        raise RuntimeError("expected built production neoth CLI is unavailable")
    results = []
    contract_failure = False
    for index, (provider, doi, claim) in enumerate(LIVE_PROBES, start=1):
        with tempfile.TemporaryDirectory(prefix=f"w404-citation-{provider}-") as temporary_home:
            home = Path(temporary_home)
            (home / "freedom.yaml").write_text("autonomy: elevated\n", encoding="utf-8")
            env = os.environ.copy()
            env["NEOTH_HOME"] = str(home)
            completed, timed_out = run(
                [str(cli), "--output", "json", "citation", "lookup", "--claim", claim, "--doi", doi, "--provider", provider],
                root,
                evidence / "logs" / f"live-{index:02d}-{provider}.log",
                45,
                env,
            )
            if timed_out:
                try:
                    receipt = parse_receipt(completed.stdout)
                except RuntimeError:
                    receipt = None
                results.append({"provider": provider, "doi": doi, "claim": claim, "exitCode": completed.returncode, "timedOut": True, "coverageEstablished": False, "outcome": "timeout:runner", "receipt": receipt, "contractFailure": False})
                continue
            try:
                receipt = parse_receipt(completed.stdout)
                covered, outcome = validate_live_receipt(receipt, provider, doi, claim)
                invalid_exit = completed.returncode != 0 and covered
                results.append({"provider": provider, "doi": doi, "claim": claim, "exitCode": completed.returncode, "timedOut": False, "coverageEstablished": covered and not invalid_exit, "outcome": outcome, "receipt": receipt, "contractFailure": invalid_exit})
                contract_failure = contract_failure or invalid_exit
            except (RuntimeError, AttributeError, TypeError, ValueError) as error:
                results.append({"provider": provider, "doi": doi, "claim": claim, "exitCode": completed.returncode, "timedOut": False, "coverageEstablished": False, "outcome": "contract_error", "receipt": None, "contractFailure": True, "error": str(error)})
                contract_failure = True
    write_json(evidence / "receipt" / "live-probes.json", {
        "schema": "neoth-w404-citation-live-probes/v3",
        "sourceHead": git_head(root),
        "ordinaryPolicy": "one fresh isolated NEOTH_HOME/freedom.yaml per provider with autonomy: elevated; production ExternalHttpAuthorizer interactive path",
        "coverageEstablished": all(item["coverageEstablished"] for item in results),
        "contractFailure": contract_failure,
        "probes": results,
    })
    return 1 if contract_failure else 0

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("native", "live"))
    parser.add_argument("--repository", required=True)
    parser.add_argument("--evidence-dir", required=True)
    parser.add_argument("--expected-head", required=True)
    parser.add_argument("--cli-bin")
    args = parser.parse_args()
    if args.mode == "native":
        return native(args)
    if not args.cli_bin:
        parser.error("live mode requires --cli-bin")
    return live(args)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f"W404 citation acceptance error: {error}", file=sys.stderr)
        raise SystemExit(2)