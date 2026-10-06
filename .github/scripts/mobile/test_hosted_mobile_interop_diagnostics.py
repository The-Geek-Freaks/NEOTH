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


if __name__ == "__main__":
    unittest.main()
