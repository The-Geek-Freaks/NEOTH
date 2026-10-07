"""Hosted-only tests for bounded, scoped daemon evidence collection."""
from __future__ import annotations

import ctypes
import importlib.util
import pathlib
import queue
import tempfile
import time
import unittest


MODULE_PATH = pathlib.Path(__file__).with_name("hosted-mobile-interop.py")
SPEC = importlib.util.spec_from_file_location("hosted_mobile_interop_diagnostics", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
INTEROP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(INTEROP)

PAIR = b"NEOTH_COMPANION_CONNECT_PHASE=pair_handshake_dispatch_received\n"
ACTIVE = b"NEOTH_COMPANION_CONNECT_PHASE=active_handshake_dispatch_received\n"
ACTIVE_REPLY_ACCEPTED = b"NEOTH_COMPANION_CONNECT_PHASE=active_handshake_reply_udp_accepted\n"
PAIR_REPLY_QUEUED = b"NEOTH_COMPANION_CONNECT_PHASE=pair_handshake_reply_udp_queued\n"
PAIR_OS_SEND_SUCCEEDED = b"NEOTH_COMPANION_CONNECT_PHASE=pair_handshake_reply_udp_os_send_succeeded\n"
ACTIVE_OS_SEND_FAILED = b"NEOTH_COMPANION_CONNECT_PHASE=active_handshake_reply_udp_os_send_failed\n"
PAIR_OS_SEND_DROPPED = b"NEOTH_COMPANION_CONNECT_PHASE=pair_handshake_reply_udp_os_send_dropped\n"
PAIR_CLIENT_UDX_ADMITTED = b"NEOTH_COMPANION_CONNECT_PHASE=pair_client_udx_route_admitted\n"
ACTIVE_SERVER_UDX_REJECTED = b"NEOTH_COMPANION_CONNECT_PHASE=active_server_udx_route_rejected\n"
PAIR_SERVER_UDX_UNKNOWN = b"NEOTH_COMPANION_CONNECT_PHASE=pair_server_udx_route_unknown_fallback\n"
ACTIVE_CLIENT_UDX_ADMITTED = b"NEOTH_COMPANION_CONNECT_PHASE=active_client_udx_route_admitted\n"
UNSCOPED_CLIENT_RESPONSE = b"NEOTH_COMPANION_CLIENT_RESPONSE_PHASE=client_udx_route_admitted\n"


class ChunkStream:
    def __init__(self, chunks: list[bytes]) -> None:
        self.chunks = iter(chunks)

    def read(self, _size: int) -> bytes:
        return next(self.chunks, b"")

    def close(self) -> None:
        pass


class ControlledStream:
    def __init__(self) -> None:
        self.chunks: queue.Queue[bytes] = queue.Queue()

    def read(self, _size: int) -> bytes:
        return self.chunks.get(timeout=5)

    def close(self) -> None:
        pass


class ScopedCollectorTests(unittest.TestCase):
    def test_pair_rpc_parse_subtype_uses_complete_fixed_display_strings(self) -> None:
        delimiter = b"companion v3 daemon unavailable: malformed RPC response"
        header = b"companion v3 daemon unavailable: malformed RPC response header"
        self.assertEqual(INTEROP.pair_cli_failure_parse_subtype(delimiter), "delimiter")
        self.assertEqual(INTEROP.pair_cli_failure_parse_subtype(header), "header")
        self.assertEqual(
            INTEROP.pair_cli_failure_parse_subtype(b"Error: " + delimiter), "delimiter"
        )
        self.assertEqual(
            INTEROP.pair_cli_failure_parse_subtype(
                b"Caused by:\n   0: mint v3 pairing invite from running daemon: " + header
            ),
            "header",
        )

    def test_pair_rpc_parse_subtype_covers_fixed_enum_and_discards_unknown_bytes(self) -> None:
        for message, subtype in INTEROP.PAIR_RPC_PARSE_FAILURES:
            self.assertEqual(INTEROP.pair_cli_failure_parse_subtype(message.encode("ascii")), subtype)
        for prefix, subtype in INTEROP.PAIR_RPC_PARSE_FAILURE_PREFIXES:
            self.assertEqual(
                INTEROP.pair_cli_failure_parse_subtype((prefix + "formatter detail").encode("ascii")),
                subtype,
            )
        secret = b"receipt-secret-must-not-persist"
        malicious = b"companion v3 daemon unavailable: malformed RPC response " + secret
        self.assertEqual(INTEROP.pair_cli_failure_parse_subtype(malicious), "unknown")
        self.assertEqual(
            INTEROP.pair_cli_failure_parse_subtype(
                b"Error: mint v3 pairing invite from running daemon: " + malicious
            ),
            "unknown",
        )
        self.assertEqual(
            INTEROP.pair_cli_failure_parse_subtype(
                b"companion v3 daemon unavailable: invalid RPC header: formatter detail"
            ),
            "unknown",
        )
        self.assertNotIn(secret.decode("ascii"), INTEROP.pair_cli_failure_parse_subtype(malicious))

    def test_pair_mint_invoke_carries_closed_parse_subtype_without_spawning(self) -> None:
        original_run = INTEROP.subprocess.run
        calls: list[object] = []
        result = type("Completed", (), {
            "returncode": 7,
            "stdout": b"",
            "stderr": b"companion v3 daemon unavailable: malformed RPC response header",
        })()
        def fake_run(*args: object, **kwargs: object) -> object:
            calls.append((args, kwargs))
            return result
        INTEROP.subprocess.run = fake_run
        try:
            with self.assertRaises(INTEROP.CliFailure) as raised:
                INTEROP.invoke(["not-run"], {}, 1.0, pair_mint=True)
        finally:
            INTEROP.subprocess.run = original_run
        self.assertEqual(len(calls), 1)
        self.assertEqual(raised.exception.parse_subtype, "header")
        self.assertEqual(raised.exception.category, "daemon_rpc_malformed_response")

    def test_pair_readiness_terminal_markers_are_closed_and_secret_free(self) -> None:
        secret = b"must-not-retain-pair-error-detail"
        stream = ChunkStream([
            b"NEOTH_COMPANION_PAIR_PHASE=readiness_owner_deadline\n",
            b"NEOTH_COMPANION_PAIR_PHASE=teardown_started\n",
            b"NEOTH_COMPANION_PAIR_PHASE=teardown_completed\n",
            b"NEOTH_COMPANION_PAIR_PHASE=failed.initial_discovery_started\n",
            b"NEOTH_COMPANION_PAIR_PHASE=readiness_owner_ended_extra\n" + secret,
        ])
        markers = INTEROP.ShutdownMarkerCollector(stream).snapshot(5)["pair_markers"]
        self.assertTrue(markers["readiness_owner_deadline"])
        self.assertTrue(markers["teardown_started"])
        self.assertTrue(markers["teardown_completed"])
        self.assertTrue(markers["failed.initial_discovery_started"])
        self.assertFalse(markers["readiness_owner_ended"])
        self.assertNotIn(secret.decode("ascii"), repr(markers))

    def test_chunk_boundaries_do_not_duplicate_or_merge_pair_and_active_markers(self) -> None:
        private_canary = b"discard-this-raw-daemon-text"
        stream = ChunkStream([
            private_canary + PAIR,
            b"x",  # The retained overlap still contains the shorter pair marker.
            ACTIVE[:31],
            ACTIVE[31:] + ACTIVE + b"[neoth pan",
            b"ic] ts_unix=1 at private-path-not-retained: secret-payload",
            b"thread 'worker' pani",
            b"cked at also-private-default-panic",
            b"NEOTH_COMPANION_CONNECT_PHASE=active_handshake_dispatch_received_extra\n",
            b"[neoth panicx] close-but-not-custom",
        ])
        collector = INTEROP.ShutdownMarkerCollector(stream)
        result = collector.snapshot(5)
        self.assertTrue(result["reader_closed"])
        self.assertFalse(result["reader_error"])
        self.assertEqual(result["scoped_connect_counts"]["pair_handshake_dispatch_received"], 1)
        self.assertEqual(result["scoped_connect_counts"]["active_handshake_dispatch_received"], 2)
        self.assertFalse(result["scoped_connect_saturated"])
        self.assertTrue(result["rust_panic_observed"])
        self.assertNotIn(private_canary.decode(), repr(result))
        self.assertNotIn("private-path-not-retained", repr(result))
        self.assertNotIn("secret-payload", repr(result))

    def test_panic_site_accepts_only_bounded_basename_and_positive_line(self) -> None:
        secret = b"panic-payload-must-not-persist"
        stream = ChunkStream([
            b"[neoth panic] ts_unix=1 at discarded-path: " + secret + b"\n",
            b"NEOTH_PANIC_SITE=companion_runtime.rs:",
            b"2337\n",
        ])
        result = INTEROP.ShutdownMarkerCollector(stream).snapshot(5)
        self.assertTrue(result["rust_panic_observed"])
        self.assertEqual(result["rust_panic_site"], "companion_runtime.rs:2337")
        self.assertNotIn(secret.decode("ascii"), repr(result))
        self.assertNotIn("discarded-path", repr(result))

    def test_panic_site_rejects_paths_payloads_zero_and_suffixes(self) -> None:
        secret = b"panic-site-secret-must-not-persist"
        invalid = INTEROP.ShutdownMarkerCollector(ChunkStream([
            b"NEOTH_PANIC_SITE=/home/runner/src/lib.rs:17\n",
            b"NEOTH_PANIC_SITE=lib.rs:0\n",
            b"NEOTH_PANIC_SITE=lib.rs:17:" + secret + b"\n",
            b"NEOTH_PANIC_SITE=lib.rs:17 extra\n",
        ])).snapshot(5)
        self.assertIsNone(invalid["rust_panic_site"])
        self.assertNotIn(secret.decode("ascii"), repr(invalid))
        self.assertNotIn("/home/runner", repr(invalid))
        for stream in (
            ChunkStream([b"NEOTH_PANIC_SITE=before.rs:19\n[neoth panic]\n"]),
            ChunkStream([b"NEOTH_PANIC_SITE=overlap.rs:23\n", b"[neoth panic]\n"]),
        ):
            result = INTEROP.ShutdownMarkerCollector(stream).snapshot(5)
            self.assertTrue(result["rust_panic_observed"])
            self.assertIsNone(result["rust_panic_site"])

    def test_reply_boundary_markers_preserve_exact_scope_and_chunk_custody(self) -> None:
        private_canary = b"private-reply-diagnostic-must-not-persist"
        unknown_scope = b"NEOTH_COMPANION_CONNECT_PHASE=inactive_handshake_reply_udp_accepted\n"
        nonmatching_suffix = b"NEOTH_COMPANION_CONNECT_PHASE=active_handshake_reply_udp_accepted_extra\n"
        stream = ChunkStream([
            private_canary + PAIR_REPLY_QUEUED[:37],
            PAIR_REPLY_QUEUED[37:] + ACTIVE_REPLY_ACCEPTED[:29],
            ACTIVE_REPLY_ACCEPTED[29:] + unknown_scope + nonmatching_suffix,
        ])
        collector = INTEROP.ShutdownMarkerCollector(stream)
        result = collector.snapshot(5)
        counts = result["scoped_connect_counts"]
        self.assertEqual(counts["pair_handshake_reply_udp_queued"], 1)
        self.assertEqual(counts["active_handshake_reply_udp_accepted"], 1)
        self.assertEqual(counts["pair_handshake_reply_udp_accepted"], 0)
        self.assertEqual(counts["active_handshake_reply_udp_queued"], 0)
        self.assertFalse(result["scoped_connect_saturated"])
        self.assertTrue(result["reader_closed"])
        self.assertFalse(result["reader_error"])
        self.assertNotIn(private_canary.decode(), repr(result))

    def test_os_send_completion_markers_keep_pair_active_scope_and_drop_boundaries(self) -> None:
        private_canary = b"private-os-send-detail-must-not-persist"
        nonmatching_suffix = b"NEOTH_COMPANION_CONNECT_PHASE=pair_handshake_reply_udp_os_send_succeeded_extra\n"
        stream = ChunkStream([
            private_canary + PAIR_OS_SEND_SUCCEEDED[:33],
            PAIR_OS_SEND_SUCCEEDED[33:] + ACTIVE_OS_SEND_FAILED[:31],
            ACTIVE_OS_SEND_FAILED[31:] + PAIR_OS_SEND_DROPPED + nonmatching_suffix,
        ])
        collector = INTEROP.ShutdownMarkerCollector(stream)
        result = collector.snapshot(5)
        counts = result["scoped_connect_counts"]
        self.assertEqual(counts["pair_handshake_reply_udp_os_send_succeeded"], 1)
        self.assertEqual(counts["active_handshake_reply_udp_os_send_failed"], 1)
        self.assertEqual(counts["pair_handshake_reply_udp_os_send_dropped"], 1)
        self.assertEqual(counts["active_handshake_reply_udp_os_send_succeeded"], 0)
        self.assertEqual(counts["pair_handshake_reply_udp_os_send_failed"], 0)
        self.assertEqual(counts["active_handshake_reply_udp_os_send_dropped"], 0)
        self.assertFalse(result["scoped_connect_saturated"])
        self.assertTrue(result["reader_closed"])
        self.assertFalse(result["reader_error"])
        self.assertNotIn(private_canary.decode(), repr(result))


    def test_cursor_retains_prior_pair_evidence_without_counting_it_as_active(self) -> None:
        stream = ControlledStream()
        collector = INTEROP.ShutdownMarkerCollector(stream)

        def await_count(name: str, expected: int) -> None:
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                if collector.scoped_connect_cursor()["counts"][name] == expected:
                    return
                time.sleep(0.001)
            self.fail(f"collector did not observe {name}")

        try:
            stream.chunks.put(PAIR)
            await_count("pair_handshake_dispatch_received", 1)
            cursor = collector.scoped_connect_cursor()
            stream.chunks.put(PAIR + ACTIVE)
            await_count("active_handshake_dispatch_received", 1)
            result = collector.scoped_connect_since(cursor)
            self.assertEqual(result["before"]["pair_handshake_dispatch_received"], 1)
            self.assertEqual(result["before"]["active_handshake_dispatch_received"], 0)
            self.assertEqual(result["observed_delta"]["pair_handshake_dispatch_received"], 1)
            self.assertEqual(result["observed_delta"]["active_handshake_dispatch_received"], 1)
            self.assertFalse(result["emission_time_bound"])
            self.assertFalse(result["reader_error"])
            self.assertFalse(result["saturated"])
        finally:
            stream.chunks.put(b"")
            collector.thread.join(timeout=5)
        self.assertFalse(collector.thread.is_alive())


    def test_udx_route_markers_preserve_scope_role_and_terminal_outcome(self) -> None:
        stream = ChunkStream([PAIR_CLIENT_UDX_ADMITTED[:37], PAIR_CLIENT_UDX_ADMITTED[37:] + ACTIVE_SERVER_UDX_REJECTED, PAIR_SERVER_UDX_UNKNOWN + ACTIVE_CLIENT_UDX_ADMITTED])
        counts = INTEROP.ShutdownMarkerCollector(stream).snapshot(5)["scoped_connect_counts"]
        self.assertEqual(counts["pair_client_udx_route_admitted"], 1)
        self.assertEqual(counts["active_server_udx_route_rejected"], 1)
        self.assertEqual(counts["pair_server_udx_route_unknown_fallback"], 1)
        self.assertEqual(counts["active_client_udx_route_admitted"], 1)
        self.assertEqual(counts["active_client_udx_route_rejected"], 0)

    def test_udx_route_markers_ignore_unscoped_response_and_bound_duplicates(self) -> None:
        stream = ChunkStream([UNSCOPED_CLIENT_RESPONSE + PAIR_CLIENT_UDX_ADMITTED, PAIR_CLIENT_UDX_ADMITTED + b"NEOTH_COMPANION_CONNECT_PHASE=pair_client_udx_route_admitted_extra\n"])
        result = INTEROP.ShutdownMarkerCollector(stream).snapshot(5)
        self.assertEqual(result["scoped_connect_counts"]["pair_client_udx_route_admitted"], 2)
        self.assertEqual(result["scoped_connect_counts"]["active_client_udx_route_admitted"], 0)
        self.assertFalse(result["scoped_connect_saturated"])
        self.assertNotIn(UNSCOPED_CLIENT_RESPONSE.decode(), repr(result))

    def test_udx_route_cursor_keeps_pair_only_outcomes_out_of_active_delta(self) -> None:
        stream = ControlledStream(); collector = INTEROP.ShutdownMarkerCollector(stream)
        def await_count(name: str, expected: int) -> None:
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                if collector.scoped_connect_cursor()["counts"][name] == expected:
                    return
                time.sleep(0.001)
            self.fail(f"collector did not observe {name}")
        try:
            stream.chunks.put(PAIR_SERVER_UDX_UNKNOWN)
            await_count("pair_server_udx_route_unknown_fallback", 1)
            cursor = collector.scoped_connect_cursor()
            stream.chunks.put(PAIR_CLIENT_UDX_ADMITTED)
            await_count("pair_client_udx_route_admitted", 1)
            delta = collector.scoped_connect_since(cursor)["observed_delta"]
            self.assertEqual(delta["pair_client_udx_route_admitted"], 1)
            self.assertEqual(delta["active_client_udx_route_admitted"], 0)
            self.assertEqual(delta["active_server_udx_route_rejected"], 0)
        finally:
            stream.chunks.put(b""); collector.thread.join(timeout=5)
        self.assertFalse(collector.thread.is_alive())
    def test_client_route_phase_whitelist_captures_fixed_markers_only(self) -> None:
        stream = ChunkStream([
            b"NEOTH_COMPANION_CONNECT_PHASE=route_direct_selected\n",
            b"NEOTH_COMPANION_CONNECT_PHASE=route_forwarded_marker\n",
            b"NEOTH_COMPANION_CONNECT_PHASE=relay_through_started\n",
            b"NEOTH_COMPANION_CONNECT_PHASE=holepunch_started\n",
        ])
        markers = INTEROP.ShutdownMarkerCollector(stream).snapshot(5)["connect_markers"]
        self.assertTrue(markers["route_direct_selected"])
        self.assertTrue(markers["route_forwarded_marker"])
        self.assertTrue(markers["relay_through_started"])
        self.assertTrue(markers["holepunch_started"])

    def test_client_route_phase_whitelist_rejects_suffix_only_marker(self) -> None:
        stream = ChunkStream([b"NEOTH_COMPANION_CONNECT_PHASE=route_direct_selected_extra\n"])
        markers = INTEROP.ShutdownMarkerCollector(stream).snapshot(5)["connect_markers"]
        self.assertFalse(markers["route_direct_selected"])
    def test_fresh_chat_bridge_is_distinct_and_runs_actual_pair_then_chat(self) -> None:
        class FakeBridge:
            def __init__(self, identity: int) -> None:
                self.identity = identity
                self.calls: list[str] = []
                self.closed = False
            def call(self, name: str, *_args: object, timeout: float) -> tuple[int, bytes]:
                self.calls.append(name)
                if name == "neoth_companion_pair_start":
                    return INTEROP.OK, b'{"state":"paired","device_id":"chat-device","descriptor":{"route":"chat"}}'
                return INTEROP.OK, b'{"kind":"chat","outcome":"accepted","records":[]}'
            def close(self) -> None:
                self.closed = True
        created: list[FakeBridge] = []
        def factory(_library: pathlib.Path) -> FakeBridge:
            bridge = FakeBridge(len(created) + 1)
            created.append(bridge)
            return bridge
        status_bridge = factory(pathlib.Path("bridge.so"))
        receipt: dict[str, object] = {"steps": {}}
        pair, chat = INTEROP.run_chat_pair_and_start(
            factory, pathlib.Path("bridge.so"), "neoth://chat-pair", receipt, lambda: 1.0
        )
        self.assertIsNot(created[1], status_bridge)
        self.assertEqual(created[1].calls, ["neoth_companion_pair_start", "neoth_companion_chat_start"])
        self.assertTrue(created[1].closed)
        self.assertFalse(status_bridge.closed)
        self.assertEqual(pair["device_id"], "chat-device")
        self.assertEqual(chat["outcome"], "accepted")
        self.assertEqual(receipt["steps"]["chat_pair"], {"code": INTEROP.OK, "validated": True})

    def test_fresh_chat_bridge_closes_on_actual_pair_and_chat_failures(self) -> None:
        class FakeBridge:
            def __init__(self, outcome: tuple[int, bytes]) -> None:
                self.outcome = outcome
                self.closed = False
                self.calls: list[str] = []
            def call(self, name: str, *_args: object, timeout: float) -> tuple[int, bytes]:
                self.calls.append(name)
                if name == "neoth_companion_pair_start":
                    return self.outcome
                return INTEROP.FAILED, b'{"result":"failed","code":"chat_transport_failed"}'
            def close(self) -> None:
                self.closed = True
        cases = (
            (
                (INTEROP.FAILED, b'{"result":"failed","code":"pair_transport_failed"}'),
                ["neoth_companion_pair_start"],
                {"code": INTEROP.FAILED, "validated": False},
            ),
            (
                (INTEROP.OK, b'{"state":"wrong-terminal"}'),
                ["neoth_companion_pair_start"],
                None,
            ),
            (
                (INTEROP.OK, b'{"state":"paired","device_id":"chat-device","descriptor":{"route":"chat"}}'),
                ["neoth_companion_pair_start", "neoth_companion_chat_start"],
                {"code": INTEROP.OK, "validated": True},
            ),
        )
        for outcome, expected_calls, expected_step in cases:
            created: list[FakeBridge] = []
            def factory(_library: pathlib.Path, outcome: tuple[int, bytes] = outcome) -> FakeBridge:
                bridge = FakeBridge(outcome)
                created.append(bridge)
                return bridge
            receipt: dict[str, object] = {"steps": {}}
            with self.assertRaises(RuntimeError):
                INTEROP.run_chat_pair_and_start(
                    factory, pathlib.Path("bridge.so"), "neoth://chat-pair", receipt, lambda: 1.0
                )
            self.assertEqual(created[0].calls, expected_calls)
            self.assertTrue(created[0].closed)
            steps = receipt["steps"]
            if expected_step is None:
                self.assertNotIn("chat_pair", steps)
            else:
                self.assertEqual(steps["chat_pair"], expected_step)
    def test_chat_failure_terminal_outcome_accepts_only_closed_failure_enum(self) -> None:
        for outcome in INTEROP.CHAT_FAILURE_TERMINAL_OUTCOMES:
            raw = ('{"kind":"chat","schema_version":3,"outcome":"' + outcome + '"}').encode("ascii")
            self.assertEqual(
                INTEROP.chat_failure_terminal_diagnostic(raw),
                {"terminal_kind": "chat", "terminal_code": outcome, "terminal_shape_valid": True},
            )
        for code in INTEROP.CHAT_FAILED_CODES:
            self.assertEqual(
                INTEROP.chat_failure_terminal_diagnostic(
                    ('{"state":"failed","code":"' + code + '"}').encode("ascii")
                ),
                {"terminal_kind": "failed", "terminal_code": code, "terminal_shape_valid": True},
            )
        self.assertEqual(
            INTEROP.chat_failure_terminal_diagnostic(b'{"state":"cancelled"}'),
            {"terminal_kind": "cancelled", "terminal_code": "cancelled", "terminal_shape_valid": True},
        )
        for code in INTEROP.CHAT_DENIED_CODES:
            self.assertEqual(
                INTEROP.chat_failure_terminal_diagnostic(
                    ('{"state":"denied","code":"' + code + '"}').encode("ascii")
                ),
                {"terminal_kind": "denied", "terminal_code": code, "terminal_shape_valid": True},
            )
        secret = b"descriptor-or-payload-must-not-persist"
        expected = {
            "terminal_kind": INTEROP.CHAT_FAILURE_TERMINAL_SENTINEL,
            "terminal_code": "unknown",
            "terminal_shape_valid": False,
        }
        for raw in (
            b'{"kind":"chat","schema_version":3,"outcome":"accepted"}',
            b'{"state":"failed","code":"unbounded-"' + secret + b'}',
            b'{"state":"denied","code":"unknown"}',
            b'{"state":"failed","code":"invalid_server_frame","detail":"' + secret + b'"}',
            b"not-json-" + secret,
            b'{"kind":"chat","schema_version":3,"outcome":[]}',
            b'{"state":"failed","code":[]}',
            b'{"state":"denied","code":{}}',
            b'{"kind":"chat","schema_version":null,"outcome":"timeout"}',
        ):
            value = INTEROP.chat_failure_terminal_diagnostic(raw)
            self.assertEqual(value, expected)
            self.assertNotIn(secret.decode("ascii"), repr(value))

    def test_chat_start_failure_records_poll_code_terminal_enum_and_closes_bridge(self) -> None:
        class FakeBridge:
            def __init__(self, terminal: bytes) -> None:
                self.terminal = terminal
                self.calls: list[str] = []
                self.closed = False
            def call(self, name: str, *_args: object, timeout: float) -> tuple[int, bytes]:
                self.calls.append(name)
                if name == "neoth_companion_pair_start":
                    return INTEROP.OK, b'{"state":"paired","device_id":"private","descriptor":{"route":"private"}}'
                return INTEROP.FAILED, self.terminal
            def close(self) -> None:
                self.closed = True

        created: list[FakeBridge] = []
        def factory(_library: pathlib.Path) -> FakeBridge:
            bridge = FakeBridge(b'{"state":"failed","code":"invalid_server_frame"}')
            created.append(bridge)
            return bridge
        receipt: dict[str, object] = {"steps": {}}
        boundaries: list[tuple[str, bool]] = []
        def observe(boundary: str) -> None:
            boundaries.append((boundary, created[0].closed))
        with self.assertRaisesRegex(RuntimeError, "chat rejected"):
            INTEROP.run_chat_pair_and_start(
                factory,
                pathlib.Path("bridge.so"),
                "neoth://private",
                receipt,
                lambda: 1.0,
                observe,
            )
        self.assertEqual(
            created[0].calls,
            ["neoth_companion_pair_start", "neoth_companion_chat_start"],
        )
        self.assertTrue(created[0].closed)
        self.assertEqual(boundaries, [("before", False), ("after", False)])
        self.assertEqual(
            receipt["chat_start_failure"],
            {
                "bridge_poll_code": INTEROP.FAILED,
                "terminal_kind": "failed",
                "terminal_code": "invalid_server_frame",
                "terminal_shape_valid": True,
            },
        )
        self.assertNotIn("private", repr(receipt["chat_start_failure"]))
        diagnostics = {"basis": "collector_observation_cursor", "observed_delta": {"active": 0}}
        INTEROP.record_chat_start_observation(receipt, True, True, 0, diagnostics)
        self.assertTrue(receipt["chat_start_daemon_alive_before"])
        self.assertTrue(receipt["chat_start_daemon_alive_after"])
        self.assertEqual(receipt["chat_start_provider_request_delta"], 0)
        self.assertIs(receipt["chat_start_diagnostics"], diagnostics)

        class PairFailureBridge(FakeBridge):
            def call(self, name: str, *_args: object, timeout: float) -> tuple[int, bytes]:
                self.calls.append(name)
                return INTEROP.FAILED, b'{"state":"failed","code":"transport_closed"}'
        pair_failure_boundaries: list[str] = []
        failed: list[PairFailureBridge] = []
        def pair_failure_factory(_library: pathlib.Path) -> PairFailureBridge:
            bridge = PairFailureBridge(b"")
            failed.append(bridge)
            return bridge
        failed_receipt: dict[str, object] = {"steps": {}}
        with self.assertRaisesRegex(RuntimeError, "chat pair rejected"):
            INTEROP.run_chat_pair_and_start(
                pair_failure_factory,
                pathlib.Path("bridge.so"),
                "neoth://private",
                failed_receipt,
                lambda: 1.0,
                pair_failure_boundaries.append,
            )
        self.assertEqual(pair_failure_boundaries, [])
        self.assertEqual(failed[0].calls, ["neoth_companion_pair_start"])
        self.assertTrue(failed[0].closed)
        self.assertNotIn("chat_start_failure", failed_receipt)

    def test_v2_fake_ffi_retries_resize_and_releases_only_after_fixture_enters(self) -> None:
        request_id = "00000000-0000-7000-8000-000000000123"
        started_activity = (b'{"activity_schema_version":1,"request_id":"' + request_id.encode("ascii")
                            + b'","max_event_seq":1,"incomplete":false,"events":[{"event_seq":1,"ordinal":1,"phase":"started","label":"Tool call"}]}')
        settled_activity = (b'{"activity_schema_version":1,"request_id":"' + request_id.encode("ascii")
                            + b'","max_event_seq":2,"incomplete":false,"events":[{"event_seq":1,"ordinal":1,"phase":"started","label":"Tool call"},{"event_seq":2,"ordinal":1,"phase":"succeeded","label":"Tool call"}]}')
        terminal = (b'{"kind":"chat","schema_version":3,"request_id":"' + request_id.encode("ascii")
                    + b'","outcome":"accepted","records":[],"provider":null,"model":null}')
        class FakeV2:
            def __init__(self) -> None:
                self.cancelled = self.freed = 0
                self.events = [("probe", 8), ("sized", INTEROP.BUFFER_TOO_SMALL, started_activity),
                               ("sized", INTEROP.ACTIVITY, started_activity), ("enter_pending",),
                               ("probe", 8), ("sized", INTEROP.BUFFER_TOO_SMALL, settled_activity),
                               ("sized", INTEROP.ACTIVITY, settled_activity, True),
                               ("probe", len(settled_activity) + 32), ("sized", INTEROP.OK, terminal)]
            def neoth_companion_chat_start_v2(self, *_args: object) -> object: return object()
            def neoth_companion_operation_cancel(self, _op: object) -> None: self.cancelled += 1
            def neoth_companion_operation_free(self, _op: object) -> None: self.freed += 1
            def neoth_companion_operation_poll_v2(self, _op: object, out: object, _capacity: int, required: object) -> int:
                event = self.events.pop(0); target = required._obj
                if event[0] == "probe":
                    self.assert_is_none(out); target.value = event[1]; return INTEROP.BUFFER_TOO_SMALL
                if event[0] == "enter_pending":
                    counter.write_text("1", encoding="ascii"); entered.write_text("entered\n", encoding="ascii"); return INTEROP.PENDING
                self.assert_not_none(out); raw = event[2]; target.value = len(raw)
                if event[1] == INTEROP.BUFFER_TOO_SMALL:
                    if _capacity >= len(raw): raise AssertionError("resize response did not require a larger buffer")
                    return event[1]
                if _capacity < len(raw): raise AssertionError("payload delivery buffer was too small")
                if len(event) > 3 and not release.is_file(): raise AssertionError("succeeded activity arrived before fixture release")
                for index, byte in enumerate(raw): out[index] = byte
                return event[1]
            @staticmethod
            def assert_is_none(value: object) -> None:
                if value is not None: raise AssertionError("probe unexpectedly had a buffer")
            @staticmethod
            def assert_not_none(value: object) -> None:
                if value is None: raise AssertionError("sized delivery lacked a buffer")
        with tempfile.TemporaryDirectory() as root:
            counter, entered, release = (pathlib.Path(root) / name for name in ("counter", "entered", "release"))
            fake = FakeV2(); bridge = object.__new__(INTEROP.Bridge); bridge.handle = object(); bridge.lib = fake
            sleep = INTEROP.time.sleep; INTEROP.time.sleep = lambda _seconds: None
            try:
                code, raw, observed = bridge.call_chat_v2_live_activity("d", "device", "prompt", counter, entered, release, timeout=1.0)
            finally:
                INTEROP.time.sleep = sleep
            self.assertEqual(code, INTEROP.OK)
            self.assertEqual(raw, terminal, "returned length must slice a shorter terminal from an old larger activity buffer")
            self.assertTrue(release.is_file())
            self.assertTrue(observed["activity_started_seen"])
            self.assertTrue(observed["fixture_release_after_activity"])
            self.assertEqual(observed["fixture_call_count"], 1)
            self.assertEqual(fake.cancelled, 0)
            self.assertEqual(fake.freed, 1)

    def test_v2_fake_ffi_mismatched_terminal_cancels_drains_and_frees_once(self) -> None:
        request_id, wrong_id = "00000000-0000-7000-8000-000000000123", "00000000-0000-7000-8000-000000000124"
        activity = (b'{"activity_schema_version":1,"request_id":"' + request_id.encode("ascii")
                    + b'","max_event_seq":1,"incomplete":false,"events":[{"event_seq":1,"ordinal":1,"phase":"started","label":"Tool call"}]}')
        wrong_terminal = b'{"kind":"chat","schema_version":3,"request_id":"' + wrong_id.encode("ascii") + b'","outcome":"accepted","records":[],"provider":null,"model":null}'
        drain_terminal = b'{"state":"failed","code":"transport_closed"}'
        class FakeV2:
            def __init__(self) -> None:
                self.cancelled = self.freed = 0
                self.events = [("probe", len(activity)), ("sized", INTEROP.ACTIVITY, activity),
                               ("probe", len(wrong_terminal)), ("sized", INTEROP.OK, wrong_terminal),
                               ("probe", 4), ("sized", INTEROP.BUFFER_TOO_SMALL, activity), ("sized", INTEROP.ACTIVITY, activity),
                               ("probe", len(drain_terminal)), ("sized", INTEROP.FAILED, drain_terminal)]
            def neoth_companion_chat_start_v2(self, *_args: object) -> object: return object()
            def neoth_companion_operation_cancel(self, _op: object) -> None: self.cancelled += 1
            def neoth_companion_operation_free(self, _op: object) -> None: self.freed += 1
            def neoth_companion_operation_poll_v2(self, _op: object, out: object, _capacity: int, required: object) -> int:
                event = self.events.pop(0); target = required._obj
                if event[0] == "probe": target.value = event[1]; return INTEROP.BUFFER_TOO_SMALL
                raw = event[2]; target.value = len(raw)
                if event[1] == INTEROP.BUFFER_TOO_SMALL:
                    if _capacity >= len(raw): raise AssertionError("resize response did not require a larger buffer")
                    return event[1]
                if _capacity < len(raw): raise AssertionError("payload delivery buffer was too small")
                for index, byte in enumerate(raw): out[index] = byte
                return event[1]
        with tempfile.TemporaryDirectory() as root:
            counter, entered, release = (pathlib.Path(root) / name for name in ("counter", "entered", "release"))
            counter.write_text("1", encoding="ascii"); entered.write_text("entered\n", encoding="ascii")
            fake = FakeV2(); bridge = object.__new__(INTEROP.Bridge); bridge.handle = object(); bridge.lib = fake
            sleep = INTEROP.time.sleep; INTEROP.time.sleep = lambda _seconds: None
            try:
                with self.assertRaisesRegex(RuntimeError, "terminal request id differs"):
                    bridge.call_chat_v2_live_activity("d", "device", "prompt", counter, entered, release, timeout=1.0)
            finally:
                INTEROP.time.sleep = sleep
            self.assertTrue(release.is_file())
            self.assertEqual(fake.cancelled, 1)
            self.assertEqual(fake.freed, 1)
            self.assertEqual(fake.events, [], "drain must consume code-6 activity and reach an actual terminal")

    def test_v2_fake_ffi_resize_deadline_cancels_and_frees_once(self) -> None:
        class FakeV2:
            def __init__(self) -> None:
                self.cancelled = self.freed = self.resizes = 0
            def neoth_companion_chat_start_v2(self, *_args: object) -> object: return object()
            def neoth_companion_operation_cancel(self, _op: object) -> None: self.cancelled += 1
            def neoth_companion_operation_free(self, _op: object) -> None: self.freed += 1
            def neoth_companion_operation_poll_v2(self, _op: object, out: object, capacity: int, required: object) -> int:
                target = required._obj
                if out is None:
                    target.value = 1
                else:
                    self.resizes += 1
                    target.value = capacity + 1
                return INTEROP.BUFFER_TOO_SMALL
        with tempfile.TemporaryDirectory() as root:
            counter, entered, release = (pathlib.Path(root) / name for name in ("counter", "entered", "release"))
            fake = FakeV2(); bridge = object.__new__(INTEROP.Bridge); bridge.handle = object(); bridge.lib = fake
            monotonic, sleep = INTEROP.time.monotonic, INTEROP.time.sleep
            clock = [-1.0]
            def fake_monotonic() -> float:
                clock[0] += 1.0
                return clock[0]
            INTEROP.time.monotonic = fake_monotonic; INTEROP.time.sleep = lambda _seconds: None
            try:
                with self.assertRaises(INTEROP.WorkDeadline):
                    bridge.call_chat_v2_live_activity("d", "device", "prompt", counter, entered, release, timeout=10.0)
            finally:
                INTEROP.time.monotonic, INTEROP.time.sleep = monotonic, sleep
            self.assertGreater(fake.resizes, 1)
            self.assertEqual(fake.cancelled, 1)
            self.assertEqual(fake.freed, 1)

if __name__ == "__main__":
    unittest.main()
