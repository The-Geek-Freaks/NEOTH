"""Hosted-only regressions for the conversation product-journey observer."""
from __future__ import annotations

import ctypes
import importlib.util
import json
import pathlib
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location("mobile_conversation", pathlib.Path(__file__).with_name("hosted-mobile-conversation.py"))
assert SPEC is not None and SPEC.loader is not None
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)
REQUEST = "00000000-0000-4000-8000-000000000001"
CONVERSATION = "00000000-0000-4000-8000-000000000002"
FOREIGN = "00000000-0000-4000-8000-000000000003"
ROWS = [{"role": "operator", "text": M.PROMPTS[0], "truncated": False},
        {"role": "agent", "text": M.REPLIES[0], "truncated": False}]


def history(*, read: bool = False) -> dict:
    value = {"conversation_schema_version": 1, "request_id": REQUEST, "revision": 2,
             "conversation_id": CONVERSATION, "state": "available", "current_turn_committed": not read,
             "bounded_tail": True, "turns": ROWS}
    return {"kind": "conversation_history", **value} if read else value


class ConversationObserverTests(unittest.TestCase):
    def test_failure_receipt_classification_retains_no_foreign_text_ids_or_secrets(self) -> None:
        value = {"kind": "chat", "outcome": "indeterminate", "request_id": REQUEST,
                 "code": "secret-sentinel", "records": [{"text": "private-message-sentinel"}],
                 "private_session_id": FOREIGN, "seed": "private-seed-sentinel"}
        error = M.ConversationFrameError(M.H.OK, value, REQUEST)
        self.assertEqual(error.public_failure, {"poll_code": M.H.OK, "kind": "chat", "outcome": "indeterminate",
            "code": "other", "request_matches": True})
        for marker in (REQUEST, FOREIGN, "secret-sentinel", "private-message-sentinel", "private-seed-sentinel"):
            self.assertNotIn(marker, str(error))
        foreign = M.ConversationFrameError(3, {"code": "transport_closed", "request_id": FOREIGN}, REQUEST)
        self.assertEqual(foreign.public_failure["code"], "transport_closed")
        self.assertFalse(foreign.public_failure["request_matches"])
        unknown = M.ConversationFrameError(999, {"kind": "secret", "outcome": ["secret"], "code": {"secret": True}}, REQUEST)
        self.assertEqual(unknown.public_failure, {"poll_code": -1, "kind": "other", "outcome": "other", "code": "other", "request_matches": False})
    def test_chat_requires_exact_admission_context_rows_and_public_fields(self) -> None:
        value = {"kind": "chat", "schema_version": 3, "request_id": REQUEST, "outcome": "accepted",
                 "records": [{"kind": "stdout", "text": M.REPLIES[0]}], "provider": "provider-a", "model": "w2328-loopback-model",
                 "conversation_admission": {"conversation_schema_version": 1, "request_id": REQUEST, "revision": 2,
                                            "conversation_id": CONVERSATION, "incognito": False}, "conversation_history": history()}
        self.assertEqual(M.validate_chat(value, REQUEST, 2, None, rows=ROWS, reply=M.REPLIES[0]), CONVERSATION)
        for broken in (
            {**value, "request_id": FOREIGN},
            {**value, "private_session_id": "must-never-cross"},
            {**value, "conversation_history": {**history(), "turns": list(reversed(ROWS))}},
            {**value, "conversation_admission": {**value["conversation_admission"], "revision": 3}},
        ):
            with self.assertRaises(RuntimeError):
                M.validate_chat(broken, REQUEST, 2, CONVERSATION, rows=ROWS, reply=M.REPLIES[0])

    def test_read_cannot_claim_commit_or_accept_foreign_or_missing_rows(self) -> None:
        value = history(read=True)
        M.validate_history(value, REQUEST, 2, CONVERSATION, committed=False, rows=ROWS, read=True)
        for broken in (
            {**value, "current_turn_committed": True}, {**value, "conversation_id": FOREIGN},
            {**value, "turns": []}, {**value, "revision": True}, {**value, "private_session_id": FOREIGN},
        ):
            with self.assertRaises(RuntimeError):
                M.validate_history(broken, REQUEST, 2, CONVERSATION, committed=False, rows=ROWS, read=True)

    def test_poll_growth_uses_actual_returned_length_without_resending(self) -> None:
        payload = json.dumps(history(read=True)).encode()

        class Library:
            calls = 0

            def neoth_companion_conversation_poll_v1(self, operation, output, capacity, required):
                self.calls += 1
                if self.calls == 1:
                    required._obj.value = 8
                    return M.H.BUFFER_TOO_SMALL
                if self.calls == 2:
                    required._obj.value = len(payload) + 30
                    return M.H.BUFFER_TOO_SMALL
                ctypes.memset(output, 120, capacity)
                ctypes.memmove(output, payload, len(payload))
                required._obj.value = len(payload)
                return M.H.OK

        bridge = object.__new__(M.ConversationBridge)
        bridge.lib = Library()
        code, raw = bridge._conversation_poll(1, M.time.monotonic() + 5)
        self.assertEqual((code, raw), (M.H.OK, payload))
        self.assertEqual(bridge.lib.calls, 3)

    def test_growth_retains_original_deadline_and_rejects_oversized_probe(self) -> None:
        class Library:
            calls = 0

            def neoth_companion_conversation_poll_v1(self, operation, output, capacity, required):
                self.calls += 1
                required._obj.value = 8 if capacity == 0 else capacity + 1
                return M.H.BUFFER_TOO_SMALL

        bridge = object.__new__(M.ConversationBridge)
        bridge.lib = Library()
        with mock.patch.object(M.time, "monotonic", side_effect=[0.0, 0.0, 2.0]):
            with self.assertRaises(M.H.WorkDeadline):
                bridge._conversation_poll(1, 1.0)
        self.assertEqual(bridge.lib.calls, 2)
        bridge.lib = mock.Mock()
        def oversized(operation, output, capacity, required):
            required._obj.value = M.MAX_RESULT + 1
            return M.H.BUFFER_TOO_SMALL
        bridge.lib.neoth_companion_conversation_poll_v1.side_effect = oversized
        with self.assertRaises(RuntimeError):
            bridge._conversation_poll(1, M.time.monotonic() + 5)

    def test_foreign_terminal_and_read_progress_cancel_and_free_exactly_once(self) -> None:
        for initial in ((M.H.OK, {**history(read=True), "request_id": FOREIGN}),
                        (M.H.STREAM, {"kind": "chat_stream_snapshot", "request_id": REQUEST})):
            bridge = object.__new__(M.ConversationBridge)
            bridge.handle = 1
            bridge.lib = mock.Mock()
            bridge.lib.neoth_companion_conversation_start_v1.return_value = 2
            bridge._conversation_poll = mock.Mock(side_effect=[
                (initial[0], json.dumps(initial[1]).encode()), (M.H.OK, json.dumps(history(read=True)).encode())])
            with self.assertRaises(RuntimeError):
                bridge.conversation({}, FOREIGN, 2, REQUEST,
                        {"operation": "history", "conversation_id": CONVERSATION}, 5)
            bridge.lib.neoth_companion_conversation_start_v1.assert_called_once()
            bridge.lib.neoth_companion_operation_cancel.assert_called_once_with(2)
            bridge.lib.neoth_companion_operation_free.assert_called_once_with(2)


    def test_start_v2_selects_v2_once_and_default_keeps_v1_once(self) -> None:
        bridge = object.__new__(M.ConversationBridge)
        bridge.handle = 1
        bridge.lib = mock.Mock()
        bridge.lib.neoth_companion_conversation_start_v2.return_value = 21
        bridge.lib.neoth_companion_conversation_start_v1.return_value = 22
        terminal = json.dumps({"kind": "chat", "request_id": REQUEST}).encode()
        bridge._conversation_poll = mock.Mock(side_effect=[(M.H.OK, terminal), (M.H.OK, terminal)])
        action = {"operation": "new", "message": "m", "incognito": False}
        self.assertEqual(bridge.conversation({}, "device", 2, REQUEST, action, 5, start_v2=True), json.loads(terminal))
        self.assertEqual(bridge.conversation({}, "device", 2, REQUEST, action, 5), json.loads(terminal))
        bridge.lib.neoth_companion_conversation_start_v2.assert_called_once()
        bridge.lib.neoth_companion_conversation_start_v1.assert_called_once()
        bridge.lib.neoth_companion_operation_cancel.assert_not_called()
        self.assertEqual(bridge.lib.neoth_companion_operation_free.call_args_list, [mock.call(21), mock.call(22)])

    def test_v2_rejects_legacy_or_invalid_activity_without_resending(self) -> None:
        for activity in (
            {"kind": "chat_activity_snapshot", "request_id": REQUEST},
            {"kind": "chat_activity_snapshot_v2", "activity_schema_version": True, "request_id": REQUEST},
            {"kind": "chat_activity_snapshot_v2", "activity_schema_version": 1, "request_id": REQUEST},
            {"kind": "chat_activity_snapshot_v2", "activity_schema_version": 2, "request_id": FOREIGN},
        ):
            bridge = object.__new__(M.ConversationBridge)
            bridge.handle = 1
            bridge.lib = mock.Mock()
            bridge.lib.neoth_companion_conversation_start_v2.return_value = 23
            bridge._conversation_poll = mock.Mock(side_effect=[
                (M.H.ACTIVITY, json.dumps(activity).encode()), (M.H.OK, b'{}')])
            with self.assertRaises(RuntimeError):
                bridge.conversation({}, "device", 2, REQUEST,
                    {"operation": "new", "message": "m", "incognito": False}, 5, start_v2=True)
            bridge.lib.neoth_companion_conversation_start_v2.assert_called_once()
            bridge.lib.neoth_companion_conversation_start_v1.assert_not_called()
            bridge.lib.neoth_companion_operation_cancel.assert_called_once_with(23)
            bridge.lib.neoth_companion_operation_free.assert_called_once_with(23)

    def test_v2_accepts_v2_activity_before_terminal(self) -> None:
        bridge = object.__new__(M.ConversationBridge)
        bridge.handle = 1
        bridge.lib = mock.Mock()
        bridge.lib.neoth_companion_conversation_start_v2.return_value = 24
        activity = {"kind": "chat_activity_snapshot_v2", "activity_schema_version": 2,
                    "request_id": REQUEST, "max_event_seq": 1, "incomplete": False,
                    "events": [{"event_seq": 1, "ordinal": 1, "phase": "started", "label": "Tool call"}]}
        terminal = {"kind": "chat", "request_id": REQUEST}
        bridge._conversation_poll = mock.Mock(side_effect=[
            (M.H.ACTIVITY, json.dumps(activity).encode()), (M.H.OK, json.dumps(terminal).encode())])
        self.assertEqual(bridge.conversation({}, "device", 2, REQUEST,
            {"operation": "new", "message": "m", "incognito": False}, 5, start_v2=True), terminal)
        bridge.lib.neoth_companion_conversation_start_v2.assert_called_once()
        bridge.lib.neoth_companion_conversation_start_v1.assert_not_called()
        bridge.lib.neoth_companion_operation_cancel.assert_not_called()
        bridge.lib.neoth_companion_operation_free.assert_called_once_with(24)


if __name__ == "__main__":
    unittest.main()
