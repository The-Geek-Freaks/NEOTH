# W119 — bounded Windows preview GUI completion window

GitHub preview `35534407998` on source `7909081e` completed the CLI build in
46 minutes and built migration/relay. The native GUI step ran from
20:56:15 to 21:56:16 UTC on 2026-09-20 and failed with the explicit runner
message that its 60-minute limit was exceeded. Its last GUI warnings appeared
at 21:44:54; the retained log contains no compiler error. Portable acceptance
did not run, so this is not a usable or qualified preview result.

The GUI step now has 90 minutes and the outer job 360 minutes. The declared
bounded steps total 332 minutes, preserving the existing 28-minute reserve.
One Cargo worker, the compiler and static CRT identity, preview-fast-v1 profile,
build commands, cache provenance and acceptance limits remain unchanged.
The cadence regression binds those limits and the retained resource/profile
settings. A fresh GitHub-hosted preview must establish actual completion and
run the existing lifecycle and diff-impact acceptance checks.

This change applies only to GitHub-hosted builds. All local validation remains
suspended. The larger allowance is not a successful-build or release claim.
