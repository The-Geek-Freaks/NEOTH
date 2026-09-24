"""Narrow receipt-custody regression checks for the hosted n8n canary."""

from __future__ import annotations

import sys
import copy
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import n8n_bootstrap_canary as canary
import n8n_template_execution_canary as execution


def inspect_failure(message: str) -> canary.Result:
    return canary.Result(1, b"", message.encode("utf-8"), False, False)


class ProveAbsentTests(unittest.TestCase):
    def assert_absent(self, kind: str, identifier: str, diagnostic: str) -> None:
        with patch.object(canary, "daemon_healthy", return_value=True), patch.object(
            canary, "run", return_value=inspect_failure(diagnostic)
        ):
            canary.prove_absent(kind, identifier)

    def assert_unproven(self, kind: str, identifier: str, diagnostic: str) -> None:
        with patch.object(canary, "daemon_healthy", return_value=True), patch.object(
            canary, "run", return_value=inspect_failure(diagnostic)
        ), self.assertRaisesRegex(canary.CanaryFailure, f"{kind}_absence_unproven"):
            canary.prove_absent(kind, identifier)

    def test_accepts_exact_missing_container_diagnostic(self) -> None:
        identifier = "0123456789abcdef"
        self.assert_absent("container", identifier, f"Error response from daemon: No such container: {identifier}")

    def test_accepts_exact_missing_volume_diagnostic(self) -> None:
        identifier = "neoth_n8n_canary_0123"
        self.assert_absent("volume", identifier, f"Error response from daemon: get {identifier}: no such volume")

    def test_rejects_missing_diagnostic_for_another_identifier(self) -> None:
        self.assert_unproven("container", "expected-id", "Error response from daemon: No such container: other-id")

    def test_rejects_missing_diagnostic_with_identifier_prefix_collision(self) -> None:
        self.assert_unproven("container", "expected-id", "Error response from daemon: No such container: expected-id-extra")

    def test_rejects_arbitrary_nonzero_inspect_failure(self) -> None:
        self.assert_unproven("volume", "neoth_n8n_canary_0123", "Error response from daemon: connection refused")


class WorkflowPayloadTests(unittest.TestCase):
    def test_mapper_strips_output_only_fields_but_requires_inactive_source(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "workflow.json"
            path.write_text('{"name":"x","active":false,"nodes":[{}],"connections":{},"settings":{},"tags":[],"description":"picker metadata"}', encoding="utf-8")
            self.assertEqual(canary.workflow_payload(path), {"name": "x", "nodes": [{}], "connections": {}, "settings": {}})

    def test_mapper_rejects_missing_settings(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "workflow.json"
            path.write_text('{"name":"x","active":false,"nodes":[{}],"connections":{}}', encoding="utf-8")
            with self.assertRaises(canary.CanaryFailure):
                canary.workflow_payload(path)


class ExecutionTemplateTests(unittest.TestCase):
    def test_adaptation_only_changes_run_only_trigger_configuration_and_credentials(self) -> None:
        repository = Path(__file__).resolve().parents[2]
        source = __import__("json").loads((repository / "SRC/neothd/assets/n8n_workflows/morning_brief.json").read_bytes())
        mapped = execution.adapt_workflow(canary, source, "credential-id", "credential-name")
        self.assertEqual(source["nodes"][0]["type"], "n8n-nodes-base.scheduleTrigger")
        self.assertEqual(mapped["nodes"][0]["type"], "n8n-nodes-base.manualTrigger")
        self.assertEqual(mapped["nodes"][0]["parameters"], {})
        self.assertEqual(mapped["connections"], source["connections"])
        self.assertEqual([node["id"] for node in mapped["nodes"]], [node["id"] for node in source["nodes"]])
        self.assertEqual([node["name"] for node in mapped["nodes"]], [node["name"] for node in source["nodes"]])
        assignments = mapped["nodes"][1]["parameters"]["assignments"]["assignments"]
        self.assertEqual({row["name"]: row["value"] for row in assignments}, {
            "neothBaseUrl": execution.FIXTURE_BASE_URL,
            "channel": execution.FIXTURE_CHANNEL,
            "recipient": execution.FIXTURE_RECIPIENT,
        })
        requests = [node for node in mapped["nodes"] if node["type"] == "n8n-nodes-base.httpRequest"]
        self.assertEqual(len(requests), 3)
        self.assertTrue(all(node["credentials"] == {"httpHeaderAuth": {"id": "credential-id", "name": "credential-name"}} for node in requests))
        self.assertEqual(requests[0]["parameters"]["jsonBody"], source["nodes"][2]["parameters"]["jsonBody"])

    def test_credential_non_success_is_unknown_and_not_retried(self) -> None:
        with patch.object(canary, "workflow_request", return_value=(400, {"message": "bad DTO"})) as request:
            with self.assertRaisesRegex(canary.UnknownEffect, "credential_create_unknown"):
                execution.create_credential(canary, 45678, "fixture-key", "fixture", "fixture-token")
        request.assert_called_once()

    def test_mock_identity_requires_the_fixture_network_alias(self) -> None:
        row = {
            "Id": "a" * 64,
            "Config": {"Image": canary.IMAGE, "Labels": {
                "io.neoth.managed": "n8n", "io.neoth.n8n-job": "fixture-job", "io.neoth.canary-kind": "mock",
            }},
            "NetworkSettings": {"Networks": {"fixture-network": {"Aliases": ["neoth-mock"]}}, "Ports": {}},
            "HostConfig": {"PortBindings": {}},
        }
        self.assertEqual(execution._owned_mock(canary, row, "fixture-job", "fixture-network"), "a" * 64)
        row["NetworkSettings"]["Networks"]["fixture-network"]["Aliases"] = []
        with self.assertRaisesRegex(canary.CanaryFailure, "mock_network_or_port_mismatch"):
            execution._owned_mock(canary, row, "fixture-job", "fixture-network")

    def test_credential_failure_uses_the_injected_callers_exception_identity(self) -> None:
        class CallerUnknown(Exception):
            pass
        caller = SimpleNamespace(UnknownEffect=CallerUnknown, workflow_request=MagicMock(return_value=(400, {})))
        with self.assertRaises(CallerUnknown):
            execution.create_credential(caller, 45678, "fixture-key", "fixture", "fixture-token")
        caller.workflow_request.assert_called_once()

    def test_mock_receipt_rejects_missing_incognito_and_extra_calls(self) -> None:
        class CallerFailure(Exception):
            pass
        valid = [
            {"path": "/api/recall", "method": "POST", "auth": True, "limit": 3},
            {"path": "/api/provider/call", "method": "POST", "auth": True, "incognito": True, "promptHasRecall": True},
            {"path": "/api/channel/send", "method": "POST", "auth": True, "channel": execution.FIXTURE_CHANNEL, "recipient": execution.FIXTURE_RECIPIENT, "textHasCompletion": True},
        ] * 2
        caller = SimpleNamespace(CanaryFailure=CallerFailure, docker=MagicMock(), sanitize_json=MagicMock())
        for calls in (valid + [valid[0]], [{**row, "incognito": False} if index == 1 else row for index, row in enumerate(valid)]):
            with self.subTest(calls=len(calls)):
                caller.sanitize_json.return_value = {"calls": calls}
                with self.assertRaises(CallerFailure):
                    execution._assert_mock_receipt(caller, "mock-id")

    def test_cli_failure_is_unknown_and_never_retried(self) -> None:
        class CallerUnknown(Exception):
            pass
        caller = SimpleNamespace(
            UnknownEffect=CallerUnknown,
            STARTUP_TIMEOUT=5,
            run=MagicMock(return_value=canary.Result(1, b"", b"", False, False)),
        )
        receipt = {}
        with self.assertRaises(CallerUnknown):
            execution._run_cli_once(caller, "execution-id", "workflow-id", receipt)
        caller.run.assert_called_once()
        self.assertEqual(receipt["unknown_effect_stage"], "n8n_execute_unknown")

    def test_execution_key_rejects_missing_or_mismatched_hashes(self) -> None:
        good = "a" * 64
        for observed, receipt in (({"ok": True, "encryptionKeySha256": good}, {}), ({"ok": True}, {"encryption_key_sha256": good}), ({"ok": True, "encryptionKeySha256": "b" * 64}, {"encryption_key_sha256": good})):
            with self.subTest(observed=observed, receipt=receipt):
                with self.assertRaisesRegex(canary.CanaryFailure, "execution_encryption_key_handoff_unproven"):
                    execution._assert_execution_key(canary, observed, receipt)

    def test_cleanup_attempts_mock_after_execution_cleanup_failure(self) -> None:
        caller = SimpleNamespace(
            inspect=MagicMock(return_value={"Labels": {"io.neoth.managed": "n8n", "io.neoth.n8n-job": "fixture-job", "io.neoth.canary-kind": "execution-network"}}),
            docker=MagicMock(),
            prove_absent=MagicMock(),
            CanaryFailure=canary.CanaryFailure,
        )
        with patch.object(execution, "_cleanup_container", side_effect=[False, True]) as cleanup:
            self.assertFalse(execution._cleanup_execution_resources(caller, {}, "network", "execution", "id1", "mock", "id2", "fixture-job", "volume"))
        self.assertEqual(cleanup.call_count, 2)


class WorkflowImportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.repository = Path(__file__).resolve().parents[2]

    def test_ambiguous_create_is_recorded_once_and_never_retried(self) -> None:
        for result in (OSError("lost reply"), canary.CanaryFailure("body limit"),
                       (201, None), (201, {"id": ""}), (403, {})):
            with self.subTest(result=result):
                receipt = {}
                with patch.object(canary, "workflow_request", side_effect=[
                    (200, {"data": []}), result,
                ]) as request, self.assertRaises(canary.UnknownEffect):
                    canary.import_workflows(self.repository, 45678, "fixture-key", receipt)
                self.assertEqual([call.args[2] for call in request.call_args_list], ["GET", "POST"])
                self.assertEqual(receipt["unknown_effect_stage"], "workflow_create_morning_brief.json")
                self.assertEqual(receipt["workflow_import_stages"], ["workflow_list_passed"])

    def test_all_assets_are_created_once_then_read_by_exact_encoded_id(self) -> None:
        calls = []
        created = {}

        def request(port, key, method, path, payload=None):
            calls.append((method, path, payload))
            if path == "/api/v1/workflows?limit=1":
                return 200, {"data": []}
            if method == "POST":
                self.assertNotIn("active", payload)
                self.assertNotIn("tags", payload)
                self.assertNotIn("description", payload)
                self.assertIsInstance(payload["settings"], dict)
                identifier = f"fixture/{len(created)}?encoded"
                created[canary.quote(identifier, safe="")] = {**payload, "id": identifier, "active": False}
                return 201, {"id": identifier}
            return 200, created[path.removeprefix("/api/v1/workflows/")]

        receipt = {}
        with patch.object(canary, "workflow_request", side_effect=request):
            canary.import_workflows(self.repository, 45678, "fixture-key", receipt)
        self.assertEqual([method for method, _, _ in calls], ["GET", "POST", "GET", "POST", "GET", "POST", "GET"])
        self.assertEqual(len(receipt["workflow_import_stages"]), 4)
        self.assertEqual(set(receipt["workflow_asset_sha256"]), set(canary.WORKFLOW_ASSETS))
        self.assertNotIn("unknown_effect_stage", receipt)

    def test_readback_rejects_wrong_identity_or_active_workflow(self) -> None:
        payload = canary.workflow_payload(self.repository / "SRC/neothd/assets/n8n_workflows/morning_brief.json")
        for change in ({"id": "other"}, {"active": True}, {"name": "other"}, {"nodes": []}):
            with self.subTest(change=change):
                readback = {**payload, "id": "owned", "active": False, **change}
                receipt = {}
                with patch.object(canary, "workflow_request", side_effect=[
                    (200, {"data": []}), (201, {"id": "owned"}), (200, readback),
                ]) as request, self.assertRaisesRegex(canary.CanaryFailure, "workflow_read_verification_failed"):
                    canary.import_workflows(self.repository, 45678, "fixture-key", receipt)
                self.assertEqual(request.call_count, 3)
                self.assertEqual(receipt["workflow_import_stages"], ["workflow_list_passed"])

    def test_readback_requires_actual_submitted_graph_and_settings(self) -> None:
        original = canary.workflow_payload(self.repository / "SRC/neothd/assets/n8n_workflows/morning_brief.json")
        original["settings"] = {"timezone": "Europe/Berlin"}
        for field in ("nodes", "connections", "extra_connection", "settings", "name"):
            with self.subTest(field=field):
                readback = copy.deepcopy({**original, "id": "owned", "active": False})
                if field == "nodes":
                    readback["nodes"][0]["parameters"] = {"changed": True}
                elif field == "connections":
                    readback["connections"] = {}
                elif field == "extra_connection":
                    readback["connections"]["unexpected"] = {"main": [[]]}
                elif field == "settings":
                    readback["settings"]["timezone"] = "UTC"
                else:
                    readback["name"] = "different workflow"
                receipt = {}
                with patch.object(canary, "workflow_payload", return_value=original), patch.object(
                    canary, "workflow_request", side_effect=[
                        (200, {"data": []}), (201, {"id": "owned"}), (200, readback),
                    ]
                ), self.assertRaisesRegex(canary.CanaryFailure, "workflow_read_verification_failed"):
                    canary.import_workflows(self.repository, 45678, "fixture-key", receipt)
                self.assertEqual(receipt["workflow_import_stages"], ["workflow_list_passed"])

    def test_readback_allows_server_added_defaults_but_not_value_coercion(self) -> None:
        self.assertTrue(canary.workflow_matches_payload(
            {"settings": {}, "nodes": [{"id": "one"}], "connections": {}},
            {"settings": {"executionOrder": "v1"}, "nodes": [{"id": "one"}], "connections": {}},
        ))
        self.assertFalse(canary.preserves_submitted_fields({"enabled": False}, {"enabled": 0}))


class ReadinessTests(unittest.TestCase):
    def test_startup_200_without_ready_body_cannot_reach_authenticated_probe(self) -> None:
        connection = MagicMock()
        with patch.object(canary.http.client, "HTTPConnection", return_value=connection), patch.object(
            canary, "http_response", return_value=(200, b'{"status":"starting"}')
        ), patch.object(canary.time, "monotonic", side_effect=[0, 0, 61]), patch.object(
            canary.time, "sleep"
        ), self.assertRaisesRegex(canary.ProbeFailure, "final_readiness_probe_failed"):
            canary.final_host_probe(45678, "never-transmitted-key")
        connection.request.assert_called_once_with(
            "GET", "/healthz/readiness", headers={"Connection": "close"}
        )

    def test_ready_signal_precedes_strict_negative_and_authenticated_probes(self) -> None:
        connection = MagicMock()
        with patch.object(canary.http.client, "HTTPConnection", return_value=connection), patch.object(
            canary, "http_response", side_effect=[
                (503, b'{"status":"error"}'),
                (200, b'{"status":"ok"}'),
                (401, b'{}'),
                (200, b'{"data":[]}'),
            ]
        ), patch.object(canary.time, "sleep"):
            result = canary.final_host_probe(45678, "fixture-key")
        self.assertEqual(result, {"negativeStatus": 401, "positiveStatus": 200})
        calls = connection.request.call_args_list
        self.assertEqual([call.args[1] for call in calls], [
            "/healthz/readiness", "/healthz/readiness",
            "/api/v1/workflows?limit=1", "/api/v1/workflows?limit=1",
        ])
        self.assertTrue(all("X-N8N-API-KEY" not in call.kwargs["headers"] for call in calls[:3]))
        self.assertEqual(calls[3].kwargs["headers"]["X-N8N-API-KEY"], "fixture-key")


if __name__ == "__main__":
    unittest.main()
