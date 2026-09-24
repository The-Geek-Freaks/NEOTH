"""Narrow receipt-custody regression checks for the hosted n8n canary."""

from __future__ import annotations

import sys
import copy
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import n8n_bootstrap_canary as canary


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
