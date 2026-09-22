# W187 — targeted A130 CI repair set

W187 consolidates narrow source repairs derived from full CI `35677727994` on
`a130526e`. That run failed with five Linux lint diagnostics, 20 distinct
Windows failures and 21 macOS failures. The repairs are not proof that the
failures are resolved: the integrated source review is complete, but fresh
GitHub-hosted execution on the repaired source is still required.

The retained source receipts under `work/gold-20260906/wave187-ci-repair/`
describe these slices:

- native-path repairs canonicalize legitimate macOS fixture roots without
  weakening production redirect checks, correct the WAL fixture topology,
  make DOI scheme/host matching case-insensitive only for `http(s)` and
  `doi.org`, and request `FILE_READ_ATTRIBUTES` for the Windows private-child
  directory handle before its existing identity inspection;
- yearly repair recognizes the adapter's exact Windows create-new collision,
  then reopens the bound child and accepts only byte-identical winner receipts;
  changed inputs remain conflicts;
- chat fixtures wait until their pending provider state before bounding
  cancellation settlement, retain the normal unavailable notice, and reject
  pre-existing Unix response-feedback namespaces that are public or
  foreign-owned without chmod recovery. This is an explicit check on feedback
  reads/writes; generic child opening retains its existing behavior for
  Obsidian and credential migration;
- daemon fixtures call the installed skill explicitly, seed scheduler state
  from the accepted pre-reload desired set, and retain the necessary
  test-only provider authorization while still proving the MCP deny precedes
  stdio transport;
- attachment/channel source gates now check the current contextual dispatch
  and prompt-tax contracts, while the CLI parity inventory records the real
  nested backup and Ollama leaves without converting source wiring into runtime
  acceptance.

The three stale provider-callsite signatures are updated from the actual A130
Hosted result only after classifying the current receivers and arguments.
Chat, raw permit delegation and sub-agent requests still enter their canonical
authorization boundaries; no local source parser generated replacement values.

W187 also contains the W180 portable diff-impact fixture correction. Preview
`35671504968` on `850aad7e` passed CLI, migration, relay, desktop-GUI build and
lifecycle scopes but failed the caller-edge condition. The fixture now puts the
changed symbol and its caller in different files so the required concrete
cross-file edge remains a real requirement. A new preview is pending.

No W187 repair closes a Road checkbox or establishes a release, product,
native, GUI, channel, audio, or runtime claim. No local compiler, Cargo,
formatter, parser, fixture, product or test executable ran under the BSOD
hold; the retained evidence is source and historical Hosted-log review only.
