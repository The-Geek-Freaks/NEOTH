"""Narrow receipt-custody regression checks for the hosted n8n canary."""

from __future__ import annotations

import sys
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
