# W195 Windows behavior repair

Hosted CI `35713920675` on `8b654ebd` finished its Windows nextest run with
17,296 cases and 13 failures. The downloaded JUnit is retained under
`work/gold-20260906/wave195-ci-behavior-repair/windows-junit/junit.xml`.

The repairs address each observed cause:

- CLI parity discovers the default operation of optional subcommands and binds
  the actual model-catalog closure. This first part was published as `432a7981`.
- The installed-Skill delegation fixture enables its exact ID in policy while
  retaining the real installation and authority proof.
- The diff-impact fixture prefixes its blank context line with a space, as
  required by unified diff. Parser rejection remains unchanged.
- Local Models preserves an operation's uncertain result when inventory omits
  its target. Restart clears stale loaded/readiness proof while retaining
  `InterruptedUnknown` and its exact operation ID, including active-at-restart.
- Windows IPC retries only `ERROR_PIPE_BUSY` during listener rotation, with
  eight 10-ms waits. Other errors and server identity checks remain unchanged.
- Streaming resampler allocation uses the existing fallible reservation path.
- Attachment and STT source gates bind the actual post-WAL finalizer and the
  contextual dispatcher carrying both WAL context and the audio permit.
- Network-construction checking admits only the reviewed loopback Local Models
  adapter. A grouped same-name macro import no longer creates a false cycle;
  two scanner regressions retain detection of actual reqwest construction.
- The pinned OpenClaw fixture names the canonical `gchat` registry ID instead
  of its `google_chat` alias; only that current mapping and its digest change.
- Subprocess bounds cover all three bounded stderr status paths.
- GUI reasoning rejects a duplicate/gapped sequence without consuming the
  prior counters. Malformed or forged frames still clear retained text.

The independent review found and corrected the restart freshness-reset defect,
then passed its focused follow-up. Source review is not runtime acceptance.
Seven previously unlisted failed native identities and the two new scanner
regressions join the canonical matrix: 598 native identities and 480 sources.

The same publication imports 48 exact Hosted formatting hunks from Preflight
`35721780428` and fixes the two compiler errors from grouped run `35721899294`:
the WAL spawn receives an owned cloned path, and capability-relative directory
enumeration uses `read_dir(".")`. The 34-test grouped lane must rerun.

Commit `4833365a` already contains the reviewed W192/W194 batch and W193 format
import despite its narrower subject. A worker committed the shared staged
batch while publishing a formatting follow-up; no source was discarded and
history was not rewritten. Git staging, commits and pushes are now root-only.
This receipt records the actual scope instead of treating that subject as proof.

No local build, formatter, code parser, test, GUI, product or audio workload ran
under the workstation BSOD hold. Fresh Hosted focused/core/full-CI gates remain
required; no Road checkbox, device or release gate is closed by this change.
