# W145 — hosted W138 compile recovery and retained loop capability

The CLI-reference build 35587747694 on 5641da2d exposed two source defects:
E0382 in the read-only Skill loader, and a missing argument in the loop engine's
MCP dispatcher call (E0061, with secondary positional E0308 diagnostics).

The loader now moves a separately named owned path into its blocking read-only
probe, retaining the borrowed input path for error diagnostics.

The loop receives its exact selected-skill capability from the existing
ProviderCallAuthorizer. A crate-visible getter borrows that capability and the
loop forwards it to every MCP round. This preserves the same route authority
already used by provider calls, including interactive and channel loop entry.
The run_loop signature stays unchanged; callers without an admitted route
retain None. No authority is reconstructed from an ID or prompt text.

The complete hosted failure log is retained with the W138 evidence. Source
review and focused regression coverage are recorded in the cumulative matrix.
Compilation and runtime acceptance remain pending fresh GitHub-hosted gates.
No local compiler, formatter, parser, test, fixture, product or GUI was run.
No Road checkbox is closed by this repair.

The real loop fixture first requires an uncapped stdio delivery and then
requires the capped identical call to leave the delivery counter unchanged.
This separates an effective cap denial from an unavailable test transport.
The cumulative matrix has 315 inputs and 167 required native identities.
