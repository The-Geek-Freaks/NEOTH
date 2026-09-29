"""Static contract tests for the hosted Google Chat relink canary; not run locally."""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import gchat_converted_relink_product_canary as canary


class GChatRelinkCanaryTests(unittest.TestCase):
    def test_refusal_failure_evidence_is_fixed_numeric_and_redacted(self):
        counts = {name: offset for offset, name in enumerate(canary.REFUSAL_COUNTERS)}
        process = subprocess.CompletedProcess(["neoth"], 1, b"", b"gchat canary key must use synthetic identity and canonical loopback token URI")
        evidence = canary.refusal_probe_evidence(
            "wrong_target", counts, process, {"before": False, "after": True}
        )
        self.assertEqual(evidence["stage"], "wrong_target")
        self.assertEqual(evidence["counters"], counts)
        self.assertEqual(evidence["index_presence"], {"before": False, "after": True})
        self.assertEqual(evidence["failure"]["stage"], "gchat_constructor")
        self.assertEqual(evidence["failure"]["reason"], "canary_synthetic_key_or_token_uri")
        self.assertEqual(evidence["failure"]["returncode"], 1)
        self.assertRegex(evidence["failure"]["output_sha256"], r"^[0-9a-f]{64}$")
        rendered = json.dumps(evidence, sort_keys=True)
        self.assertNotIn(canary.EMAIL, rendered)
        self.assertNotIn("http://", rendered)
        self.assertNotIn("BEGIN PRIVATE KEY", rendered)
        self.assertNotIn("exception", rendered)
        canary.validate_receipt_redaction(rendered)
        for forbidden in (canary.EMAIL, "http://127.0.0.1:1", "https://example.invalid", "raw exception text", "BEGIN PRIVATE KEY"):
            with self.subTest(forbidden=forbidden):
                with self.assertRaisesRegex(canary.Failure, "receipt_secret_leak"):
                    canary.validate_receipt_redaction(json.dumps({"failure": forbidden}))
        for invalid in (
            {**counts, "extra": 1},
            {name: (True if name == "token" else value) for name, value in counts.items()},
            {name: (-1 if name == "token" else value) for name, value in counts.items()},
        ):
            with self.subTest(invalid=invalid):
                with self.assertRaisesRegex(canary.Failure, "refusal_evidence_invalid"):
                    canary.refusal_probe_evidence(
                        "wrong_target", invalid, process, {"before": False, "after": True}
                    )
        with self.assertRaisesRegex(canary.Failure, "refusal_evidence_invalid"):
            canary.refusal_probe_evidence(
                "untrusted-stage", counts, process, {"before": False, "after": True}
            )
        for index_presence in (
            {"before": False},
            {"before": False, "after": True, "extra": False},
        ):
            with self.subTest(index_presence=index_presence):
                with self.assertRaisesRegex(canary.Failure, "refusal_evidence_invalid"):
                    canary.refusal_probe_evidence(
                        "wrong_target", counts, process, index_presence
                    )

    def test_refusal_diagnostic_maps_independent_current_rust_error_chains(self):
        secret = "https://127.0.0.1:12345/token bot@neoth-canary.invalid Bearer abc.def.ghi BEGIN PRIVATE KEY"
        cases = (
            (
                "candidate",
                "candidate_service_account_file",
                "converted relink candidate: Google Chat relink lacks service-account file\n" + secret,
            ),
            (
                "gchat_constructor",
                "canary_synthetic_key_or_token_uri",
                "channel readiness: gchat canary key must use synthetic identity and canonical loopback token URI\n" + secret,
            ),
            (
                "gchat_probe",
                "space_identity_mismatch",
                "Google Chat space target probe returned a different space\n" + secret,
            ),
        )
        for expected_stage, expected_reason, stderr in cases:
            with self.subTest(expected_reason=expected_reason):
                process = subprocess.CompletedProcess(["neoth"], 17, b"ignored", stderr.encode("utf-8"))
                diagnostic = canary.refusal_failure_diagnostic(process)
                self.assertEqual(diagnostic["stage"], expected_stage)
                self.assertEqual(diagnostic["reason"], expected_reason)
                self.assertEqual(diagnostic["returncode"], 17)
                self.assertEqual(diagnostic["output_sha256"], canary.refusal_output_hash(process))
                rendered = json.dumps(diagnostic, sort_keys=True)
                self.assertNotIn(secret, rendered)
                self.assertNotIn(canary.EMAIL, rendered)
                self.assertNotIn("https://", rendered)

    def test_fixed_canary_diagnostic_codes_map_without_retaining_adjacent_secret_text(self):
        secret = " https://127.0.0.1:12345/token bot@neoth-canary.invalid Bearer abc.def.ghi BEGIN PRIVATE KEY"
        for code, (expected_stage, expected_reason) in canary.GCHAT_CANARY_DIAGNOSTIC_CODES.items():
            with self.subTest(code=code):
                stderr = f"outer context: gchat canary exact target probe diagnostic: {code}{secret}"
                process = subprocess.CompletedProcess(["neoth"], 1, b"ignored", stderr.encode("utf-8"))
                diagnostic = canary.refusal_failure_diagnostic(process)
                self.assertEqual(diagnostic["stage"], expected_stage)
                self.assertEqual(diagnostic["reason"], expected_reason)
                rendered = json.dumps(diagnostic, sort_keys=True)
                self.assertNotIn(secret, rendered)
                self.assertNotIn(canary.EMAIL, rendered)
                self.assertNotIn("https://", rendered)
                self.assertNotIn("BEGIN PRIVATE KEY", rendered)

    def test_fixed_canary_diagnostic_literals_cover_each_failure_phase(self):
        secret = " https://127.0.0.1:12345/token bot@neoth-canary.invalid Bearer abc.def.ghi BEGIN PRIVATE KEY"
        cases = (
            ("preparation", "prepare-candidate", "gchat_prepare", "prepare_candidate"),
            ("probe", "constructor-key-read", "gchat_constructor", "constructor_key_read"),
            ("probe", "bearer-rsa-pem", "gchat_bearer", "bearer_rsa_pem"),
            ("probe", "token-post", "gchat_token", "token_post"),
            ("probe", "subscription-body", "gchat_subscription", "subscription_body"),
            ("probe", "space-identity", "gchat_space", "space_identity_mismatch"),
        )
        for kind, code, expected_stage, expected_reason in cases:
            with self.subTest(code=code):
                process = subprocess.CompletedProcess(
                    ["neoth"],
                    1,
                    b"ignored",
                    f"gchat canary exact target {kind} diagnostic: {code}{secret}".encode("utf-8"),
                )
                diagnostic = canary.refusal_failure_diagnostic(process)
                self.assertEqual(diagnostic["stage"], expected_stage)
                self.assertEqual(diagnostic["reason"], expected_reason)
                rendered = json.dumps(diagnostic, sort_keys=True)
                self.assertNotIn(secret, rendered)
                self.assertNotIn(canary.EMAIL, rendered)
                self.assertNotIn("https://", rendered)
                self.assertNotIn("BEGIN PRIVATE KEY", rendered)

    def test_unrecognized_fixed_canary_diagnostic_code_stays_unknown_and_redacted(self):
        secret = " https://127.0.0.1:12345/token bot@neoth-canary.invalid Bearer abc.def.ghi BEGIN PRIVATE KEY"
        process = subprocess.CompletedProcess(
            ["neoth"], 1, b"ignored", f"gchat canary exact target probe diagnostic: future-code{secret}".encode("utf-8")
        )
        diagnostic = canary.refusal_failure_diagnostic(process)
        self.assertEqual(diagnostic["stage"], "unknown")
        self.assertEqual(diagnostic["reason"], "unknown")
        rendered = json.dumps(diagnostic, sort_keys=True)
        self.assertNotIn(secret, rendered)
        self.assertNotIn(canary.EMAIL, rendered)
        self.assertNotIn("https://", rendered)

    def test_recognized_probe_unknown_is_distinct_from_absent_or_future_marker(self):
        recognized = subprocess.CompletedProcess(
            ["neoth"], 1, b"", b"gchat canary exact target probe diagnostic: unknown"
        )
        diagnostic = canary.refusal_failure_diagnostic(recognized)
        self.assertEqual(diagnostic["stage"], "gchat_probe")
        self.assertEqual(diagnostic["reason"], "probe_unclassified")
        for stderr in (b"", b"gchat canary exact target probe diagnostic: future-code"):
            with self.subTest(stderr=stderr):
                diagnostic = canary.refusal_failure_diagnostic(
                    subprocess.CompletedProcess(["neoth"], 1, b"", stderr)
                )
                self.assertEqual(diagnostic["stage"], "unknown")
                self.assertEqual(diagnostic["reason"], "unknown")

    def test_runtime_panic_hook_and_worker_join_are_fixed_and_redacted(self):
        secret = " https://127.0.0.1:12345/token bot@neoth-canary.invalid BEGIN PRIVATE KEY"
        stderr = (
            "\x1b[31m[neoth panic] ts_unix=1760000000 at src/channels/gchat.rs:411: "
            f"panic payload{secret} (version=1.2.3)\x1b[0m\n"
            "Error: neoth main worker thread panicked\n"
        )
        process = subprocess.CompletedProcess(["neoth"], 1, b"", stderr.encode("utf-8"))
        diagnostic = canary.refusal_failure_diagnostic(process)
        self.assertEqual(diagnostic["stage"], "runtime")
        self.assertEqual(diagnostic["reason"], "panic_hook_observed")
        self.assertEqual(diagnostic["returncode"], 1)
        rendered = json.dumps(diagnostic, sort_keys=True)
        self.assertNotIn(secret, rendered)
        self.assertNotIn("gchat.rs", rendered)
        self.assertNotIn("panic payload", rendered)
        canary.validate_receipt_redaction(rendered)

    def test_runtime_worker_panic_without_hook_is_fixed_and_redacted(self):
        secret = " https://127.0.0.1:12345/token bot@neoth-canary.invalid BEGIN PRIVATE KEY"
        process = subprocess.CompletedProcess(
            ["neoth"], 1, b"", f"\x1b[31mError: neoth main worker thread panicked\x1b[0m\n{secret}".encode("utf-8")
        )
        diagnostic = canary.refusal_failure_diagnostic(process)
        self.assertEqual(diagnostic["stage"], "runtime")
        self.assertEqual(diagnostic["reason"], "worker_thread_panic")
        rendered = json.dumps(diagnostic, sort_keys=True)
        self.assertNotIn(secret, rendered)
        self.assertNotIn("https://", rendered)
        canary.validate_receipt_redaction(rendered)

    def test_runtime_panic_classifier_rejects_misleading_unanchored_text(self):
        secret = " https://127.0.0.1:12345/token bot@neoth-canary.invalid BEGIN PRIVATE KEY"
        cases = (
            f"prefix [neoth panic] ts_unix=1760000000 at src/channels/gchat.rs:411: fake{secret} (version=1.2.3)",
            f"Error: neoth main worker thread panicked: fake{secret}",
            f"[neoth panic] ts_unix=not-a-number at src/channels/gchat.rs:411: fake{secret}",
        )
        for stderr in cases:
            with self.subTest(stderr=stderr.split()[0]):
                diagnostic = canary.refusal_failure_diagnostic(
                    subprocess.CompletedProcess(["neoth"], 1, b"", stderr.encode("utf-8"))
                )
                self.assertEqual(diagnostic["stage"], "unknown")
                self.assertEqual(diagnostic["reason"], "unknown")
                rendered = json.dumps(diagnostic, sort_keys=True)
                self.assertNotIn(secret, rendered)
                self.assertNotIn("https://", rendered)

    def test_refusal_diagnostic_redacts_unknown_sensitive_output(self):
        secret = b"https://127.0.0.1:12345/token bot@neoth-canary.invalid Bearer abc.def.ghi BEGIN PRIVATE KEY"
        process = subprocess.CompletedProcess(["neoth"], 1, secret, b"unrecognized failure")
        diagnostic = canary.refusal_failure_diagnostic(process)
        self.assertEqual(diagnostic["stage"], "unknown")
        self.assertEqual(diagnostic["reason"], "unknown")
        rendered = json.dumps(diagnostic, sort_keys=True)
        self.assertNotIn(secret.decode("utf-8"), rendered)
        self.assertNotIn(canary.EMAIL, rendered)
        self.assertNotIn("https://", rendered)
        self.assertNotIn("BEGIN PRIVATE KEY", rendered)
        canary.validate_receipt_redaction(rendered)

    def test_refusal_contract_failure_keeps_redacted_process_diagnostic(self):
        class NoCalls:
            def counts(self):
                return {name: 0 for name in canary.REFUSAL_COUNTERS}

        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            early = subprocess.CompletedProcess(["neoth"], 1, b"", b"gchat canary exact target preparation diagnostic: validate-request")
            with self.assertRaisesRegex(canary.Failure, "pending_index_invalid") as missing:
                canary.require_pending_unchanged(home, {}, False, "wrong_target", 1, "wrong_space", NoCalls(), early)
            self.assertEqual(missing.exception.refusal_probe["failure"]["reason"], "validate_request")
            self.assertEqual(missing.exception.refusal_probe["index_presence"], {"before": False, "after": False})
            pending = {"destination": canary.DESTINATION, "state": "pending", "id": "a" * 64, "source_set_sha256": "b" * 64}
            (home / "channel_relinks.json").write_text(json.dumps({"schema_version": 1, "pending": [pending]}), encoding="utf-8")
            process = subprocess.CompletedProcess(["neoth"], 1, b"", b"Google Chat space target probe returned a different space")
            with self.assertRaisesRegex(canary.Failure, "refusal_probe_contract_invalid") as caught:
                canary.require_pending_unchanged(home, {}, True, "wrong_returned_space", 2, "space", NoCalls(), process)
            evidence = caught.exception.refusal_probe
            self.assertEqual(evidence["stage"], "wrong_returned_space")
            self.assertEqual(evidence["failure"]["stage"], "gchat_probe")
            self.assertEqual(evidence["failure"]["reason"], "space_identity_mismatch")
            self.assertEqual(evidence["index_presence"], {"before": True, "after": True})

            class ExpectedCalls:
                def counts(self):
                    return {**NoCalls().counts(), "token": 2, "subscription": 2, "space": 1}

            proof = canary.require_pending_unchanged(home, {}, False, "wrong_returned_space", 2, "space", ExpectedCalls(), process)
            self.assertEqual(proof["index_presence"], {"before": False, "after": True})
            self.assertEqual(proof["pending_id"], pending["id"])
            self.assertEqual(proof["source_set_sha256"], pending["source_set_sha256"])

    def test_refusal_evidence_rejects_non_boolean_index_presence(self):
        process = subprocess.CompletedProcess(["neoth"], 1, b"", b"gchat canary exact target probe diagnostic: unknown")
        counts = {name: 0 for name in canary.REFUSAL_COUNTERS}
        with self.assertRaisesRegex(canary.Failure, "refusal_evidence_invalid"):
            canary.refusal_probe_evidence(
                "wrong_target", counts, process, {"before": False, "after": 1}
            )

    def test_strict_google_chat_envelope_and_public_argv(self):
        with tempfile.TemporaryDirectory() as directory:
            key = Path(directory) / "key.json"
            payload = json.loads(canary.envelope(key))
            self.assertEqual(payload, {"schema_version": 1, "channel": "gchat", "fields": {"url": str(key), "server": canary.SUBSCRIPTION, "allowed_sender": canary.ALLOWED_SENDER}})
            arguments = canary.argv(Path("/bin/neoth"), Path("/tmp/openclaw.json"), canary.SPACE)
            self.assertEqual(arguments[-4:], ["--source-account", "work", "--target", canary.SPACE])
            self.assertIn("google_chat", arguments)

    def test_ready_output_rejects_wrong_channel_identity_and_retry(self):
        good = {"channel": "gchat", "account": "default", "relink_id": "a" * 64, "state": "ready", "already_ready": False, "reload_requested": True}
        self.assertEqual(canary.validate_output(good, False), "a" * 64)
        for value in ({**good, "channel": "google_chat"}, {**good, "channel": "imessage_bluebubbles"}, {**good, "relink_id": "bad"}, {**good, "state": "pending"}, {**good, "extra": True}):
            with self.subTest(value=value):
                with self.assertRaises(canary.Failure):
                    canary.validate_output(value, False)
        with self.assertRaises(canary.Failure):
            canary.validate_output({**good, "already_ready": True}, True, "b" * 64)

    def test_material_commitment_uses_service_account_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            key = Path(directory) / "service-account.json"
            key.write_bytes(b"first")
            first = canary.material_commitment(key, canary.SPACE)
            # Independent vector from relink.rs: canonical gchat wire ID,
            # exact target, then three little-endian length-framed fields.
            self.assertEqual(first, "2e42f746a3d15efd7dbcbdbbe1d385673c56e11ad8f6fd8e013f00054dea69f8")
            key.rename(Path(directory) / "renamed.json")
            renamed = Path(directory) / "renamed.json"
            self.assertEqual(first, canary.material_commitment(renamed, canary.SPACE))
            renamed.write_bytes(b"second")
            self.assertNotEqual(first, canary.material_commitment(renamed, canary.SPACE))

    def test_ready_files_requires_external_expected_hashes_and_gchat_schema(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / "neoth-home"
            home.mkdir()
            source = root / "openclaw.json"
            source.write_text("{}", encoding="utf-8")
            key = root / "service-account.json"
            key.write_text("{}", encoding="utf-8")
            (home / "freedom.yaml").write_text("freedom", encoding="utf-8")
            (home / "credentials.yaml").write_bytes(b"NEOTH_CONF_ENCv1\ncredentials")
            route = {"destinations": {"gchat_space": canary.SPACE}}
            route_raw = json.dumps(route, indent=2).encode()
            (home / "channel_routing.json").write_bytes(route_raw)
            expected = canary.ExpectedReceipt(canary.material_commitment(key, canary.SPACE), "b" * 64, "c" * 64, canary.pair_commitment(home), canary.sha256_bytes(route_raw), canary.digest(source))
            identity = "a" * 64
            entry = {"id": identity, "destination": canary.DESTINATION, "state": "ready", "completion_request_material_sha256": expected.material_sha256, "bound_material_sha256": expected.material_sha256, "source_set_sha256": "d" * 64}
            (home / "channel_relinks.json").write_text(json.dumps({"schema_version": 1, "pending": [entry]}), encoding="utf-8")
            transaction = {"version": 1, "pending_id": identity, "destination": canary.DESTINATION, "target_sha256": canary.sha256_bytes(canary.SPACE.encode()), "request_material_sha256": expected.material_sha256, "pair_before_sha256": expected.pair_before_sha256, "routing_before_sha256": expected.routing_before_sha256, "pair_after_sha256": expected.pair_after_sha256, "routing_after_sha256": expected.routing_after_sha256, "phase": "routing_committed"}
            (home / ".channel-relink-google-chat.transaction.json").write_text(json.dumps(transaction), encoding="utf-8")
            (home / canary.RELOAD).write_text("reload", encoding="utf-8")
            self.assertIn("credentials.yaml", canary.ready_files(home, identity, expected))
            changes = (("material_sha256", "e" * 64), ("pair_before_sha256", "e" * 64), ("routing_before_sha256", "e" * 64), ("pair_after_sha256", "e" * 64), ("routing_after_sha256", "e" * 64))
            for attribute, replacement in changes:
                with self.subTest(attribute=attribute):
                    mutated = canary.ExpectedReceipt(**{**expected.__dict__, attribute: replacement})
                    with self.assertRaises(canary.Failure):
                        canary.ready_files(home, identity, mutated)
            (home / "channel_routing.json").write_text(json.dumps({"destinations": {"google_chat": canary.SPACE}}), encoding="utf-8")
            with self.assertRaises(canary.Failure):
                canary.ready_files(home, identity, expected)

    def test_fake_rejects_wrong_bearer_and_stop_is_safe_before_start(self):
        with tempfile.TemporaryDirectory() as directory:
            server = canary.FakeGoogle(Path(directory) / "public.pem")
            self.assertTrue(server.stop())
        with tempfile.TemporaryDirectory() as directory:
            server = canary.FakeGoogle(Path(directory) / "public.pem")
            server.start()
            try:
                import urllib.request
                with self.assertRaises(Exception):
                    urllib.request.urlopen(f"http://127.0.0.1:{server.port}/v1/{canary.SUBSCRIPTION}", timeout=5)
                self.assertEqual(server.counts()["bad_bearer"], 1)
            finally:
                self.assertTrue(server.stop())

    def test_source_is_googlechat_custody_only_and_json_is_strict(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "openclaw.json"
            canary.source(path)
            value = json.loads(path.read_text())
            self.assertEqual(value["channels"]["googlechat"]["accounts"]["work"]["serviceAccount"]["id"], "CANARY")
        with self.assertRaises(canary.Failure):
            canary.one_json(b'{"a":1,"a":2}')


if __name__ == "__main__":
    unittest.main()
