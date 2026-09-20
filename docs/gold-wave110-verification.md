# W110 — LINE webhook-port configuration parity

This R4-07 slice exposes the existing `line_webhook_port` setting through
`channel add line --line-webhook-port` and the LINE setup form. It uses the
existing channel transaction and private stdin envelope. The listener still
binds to loopback, requires the existing channel-secret signature verification
and exact sender policy, and remains a separate daemon-start concern.

## Intended behavior and regression boundary

- Explicit ports must be whole numbers in `1..=65535`; zero, malformed text,
  fractional input and out-of-range values are rejected before publication.
- Omitted or blank GUI input preserves an existing configured port during
  credential replacement. New configuration without a port retains the
  runtime default `8444`.
- The LINE form also gains its previously missing required sender input. The
  existing builder already required this exact sender identity; adding the
  widget makes the form capable of producing a valid admitted request.
- The private field is admitted only for LINE. The GUI sends the port with
  the credentials in its existing private stdin request, without adding
  access tokens or channel secrets to the subprocess argument list.
- Explicit removal clears the configured port. Port-only configuration is
  recognized as a removal, without claiming that a running listener was
  immediately rebound or stopped by the configuration command.

## Evidence status

Source implementation and independent review are complete; remote execution is pending. The added
regressions exercise real Clap parsing, typed private JSON, staging/removal and
the actual private request with fixed subprocess argv. The older Matrix builder
wrapper is test-only. Unknown private JSON fields remain rejected without
echoing submitted values or keys; its existing regression follows that sanitized
error boundary. Exact test identities and source hashes accompany publication. No local
compiler, formatter, parser, test, product or GUI execution is permitted under
the workstation stability constraint. The ongoing `7909081e` full CI
`35534405981` and Windows preview `35534407998` cover W108/W109, not this later
LINE source. W110 requires its own relevant remote gates.

No R4-07 or other roadmap checkbox closes. Counts remain 1324 total, 1015
checked, 307 open and 2 partial; raw unchecked309/pre-tag308.

The initial source publication deliberately recorded the generated-reference
drift as open. GitHub reference run `35535636229` successfully compiled the
current CLI on `fb383b8a` and exported its actual `completions --reference`
output. The source commit and SHA-256 were verified before copying the exact
artifact into `docs/cli-commands.md`; its only changes are the Matrix and LINE
flag entries. The unchanged docgen anti-drift test still awaits the next full
CI. W112 changes only a dispatcher test, not the command tree or generator.

The independent six-file source review and separate CLI-reference-export review
found no blocking issue. Their source hashes are retained in the batch records.

## Publication and remote formatting

W110 was published as `8b7db9a5` after independent source and workflow review. Code Quality `35535343581` passed; Preflight `35535343835` requested only two assertion-layout changes. The follow-up applies those exact remote hunks. New-source static/runtime gates and generated CLI-reference refresh remain pending.

W110 formatting head `4087983f` passed Preflight `35535462840` and Code Quality `35535462600`. Earlier-source CI `35534405981` now has ten successful component jobs but Linux stopped before tests on `await_holding_lock` in a dispatcher fixture; W112 is repairing that narrow test boundary. macOS/Windows and preview remain useful pending runs. A separate dispatch-only CLI-reference job builds the current CLI with one Cargo worker and exports source/digest-bound documentation without repository write access.

## W112 observed strict-lint follow-up

W112 (2026-09-20) repairs the observed Linux test-lock lint with a synchronous wrapper around the unchanged async dispatcher fixture. The global environment lock, restoration, current-thread runtime and all risk/receipt assertions are preserved; no lint allowance is introduced. Independent review passed. Reference run `35535636229` successfully built the W110 public CLI on `fb383b8a`; its commit/digest-verified generated Markdown now supplies the two new flag entries. Fresh strict Clippy, docgen equality and native runtime remain required on the combined source.
