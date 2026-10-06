"""Hosted-only tests for bounded, scoped daemon evidence collection."""
from __future__ import annotations

import importlib.util
import pathlib
import queue
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
    def test_chunk_boundaries_do_not_duplicate_or_merge_pair_and_active_markers(self) -> None:
        private_canary = b"discard-this-raw-daemon-text"
        stream = ChunkStream([
            private_canary + PAIR,
            b"x",  # The retained overlap still contains the shorter pair marker.
            ACTIVE[:31],
            ACTIVE[31:] + ACTIVE,
            b"NEOTH_COMPANION_CONNECT_PHASE=active_handshake_dispatch_received_extra\n",
        ])
        collector = INTEROP.ShutdownMarkerCollector(stream)
        result = collector.snapshot(5)
        self.assertTrue(result["reader_closed"])
        self.assertFalse(result["reader_error"])
        self.assertEqual(result["scoped_connect_counts"]["pair_handshake_dispatch_received"], 1)
        self.assertEqual(result["scoped_connect_counts"]["active_handshake_dispatch_received"], 2)
        self.assertFalse(result["scoped_connect_saturated"])
        self.assertNotIn(private_canary.decode(), repr(result))

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
if __name__ == "__main__":
    unittest.main()
