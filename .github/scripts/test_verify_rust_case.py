"""Closed positive/negative contracts for exact libtest result collection."""
import unittest

from verify_rust_case import verify_case

IDENTITY = "cli::chat::tests::fixture"
SUMMARY = "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 12 filtered out; finished in 0.97s"


def log(body: str) -> str:
    return f"{IDENTITY}: test\n\n1 test, 0 benchmarks\n\nrunning 1 test\ntest {IDENTITY} ... {body}\n\n{SUMMARY}\n"


class ExactRustCaseTests(unittest.TestCase):
    def test_inline_success(self):
        self.assertTrue(verify_case(IDENTITY, log("ok"), 0)["accepted"])

    def test_diagnostics_between_case_name_and_ok(self):
        text = log("[neoth] checkpoint\n[neoth:context] Preparing context\nRecorded reply.\nok")
        self.assertTrue(verify_case(IDENTITY, text, 0)["accepted"])

    def test_windows_crlf_success(self):
        self.assertTrue(verify_case(IDENTITY, log("message\nok").replace("\n", "\r\n"), 0)["accepted"])

    def test_nonzero_exit_refuses_forged_success_text(self):
        self.assertFalse(verify_case(IDENTITY, log("ok"), 101)["accepted"])

    def test_failed_summary_refuses_printed_ok(self):
        text = log("provider said ok\nok").replace(SUMMARY, "test result: FAILED. 0 passed; 1 failed; 0 ignored;")
        self.assertFalse(verify_case(IDENTITY, text, 0)["accepted"])

    def test_wrong_identity_refuses_success(self):
        self.assertFalse(verify_case("other::case", log("ok"), 0)["accepted"])

    def test_missing_discovery_refuses_success(self):
        text = log("ok").replace(IDENTITY + ": test\n", "")
        self.assertFalse(verify_case(IDENTITY, text, 0)["accepted"])

    def test_duplicate_discovery_refuses_success(self):
        self.assertFalse(verify_case(IDENTITY, IDENTITY + ": test\n" + log("ok"), 0)["accepted"])

    def test_missing_or_ambiguous_summary_refuses_success(self):
        for text in [log("ok").replace(SUMMARY, ""), log("ok") + SUMMARY + "\n"]:
            with self.subTest(text=text):
                self.assertFalse(verify_case(IDENTITY, text, 0)["accepted"])

    def test_multiple_or_ignored_cases_refuse_success(self):
        for before, after in [("running 1 test", "running 2 tests"), ("1 passed; 0 failed", "2 passed; 0 failed"), ("0 ignored", "1 ignored")]:
            with self.subTest(after=after):
                self.assertFalse(verify_case(IDENTITY, log("ok").replace(before, after), 0)["accepted"])

    def test_other_case_output_refuses_success(self):
        self.assertFalse(verify_case(IDENTITY, log("ok\ntest other::case ... ok"), 0)["accepted"])

    def test_missing_or_duplicate_split_terminal_refuses_success(self):
        for body in ["message", "message\nok\nok"]:
            with self.subTest(body=body):
                self.assertFalse(verify_case(IDENTITY, log(body), 0)["accepted"])


if __name__ == "__main__":
    unittest.main()
