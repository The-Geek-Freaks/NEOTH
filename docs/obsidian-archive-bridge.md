# Obsidian Archive Bridge

The Obsidian Archive Bridge is a local, desktop-only companion plugin for
selected NEOTH session notes. It does not expose a network service and it does
not send note text or vault paths over its plugin IPC. The daemon reopens the
approved vault and reads the selected note again before any import.

## Release state

The source tree contains plugin version `0.2.0` and the daemon/CLI pairing
surface. This is not yet a release acceptance claim: hosted plugin
`typecheck`, build, contract tests, and native daemon acceptance remain
pending. Do not treat a source checkout as an installed or accepted plugin.

## Hosted lifecycle verification

The manual `obsidian-bridge-product.yml` workflow rebuilds the locked plugin,
checks the tracked bundle for drift, runs its contract checks, and builds the
current public NEOTH CLI. A disposable daemon/home/vault then exercises the
installed bundle through a minimal Node host adapter: pairing, offline queue,
real local IPC, exact-event retry, stale-source rejection, unpair, and
install/update/repair/uninstall with retained settings and vault contents.

The adapter supplies Obsidian host methods; it does not prove execution in the
native Obsidian desktop application. Receipts distinguish source and installed
artifact hashes, product outcomes, and cleanup. A submitted workflow or a
source review alone does not establish a passed lifecycle. This combined
gate has not yet passed its hosted lifecycle.

The disposable hosted fixture provisions its own fresh WAL/config AEAD identity
before starting the daemon through the public `neoth security restore-master-key`
command. Its 32-byte raw recovery input exists only in the isolated runner root,
is never included in the receipt, and cleanup must remove it. This exercises the
supported recovery/binding contract; it does not write `wal/master.key` directly
or weaken the bridge owner's load-only key check. It is fixture setup only, not
an operator recovery instruction or a claim about an existing installation.

## Prerequisites

The instance needs an existing WAL/config AEAD master key in its own home.
Bridge startup loads that identity and fails if it is absent or invalid; it
never generates a replacement for an existing installation. The disposable
fixture provisioning above does not establish a first-use setup flow for a
new operator installation.

Run a compatible NEOTH daemon for the same user. Configure all of these in
`freedom.yaml` before pairing:

```yaml
obsidian_vault: 'C:/Users/example/Documents/NEOTH-Vault'
obsidian_vault_reader_enabled: true
obsidian_archive_bridge_enabled: true
```

The configured vault must also have an active, admitted, **accountless**
Obsidian entry in `context_connectors`. That entry is daemon policy state, not
a vault path supplied by the plugin. Merge this account into the existing
`registered_accounts` list; retain every existing account and use the exact
existing top-level `operator_id` as `subject_id`. Do not replace another
operator's ownership with this example.

```yaml
operator_id: example-operator
context_connectors:
  schema_version: 1
  enabled: true
  registered_accounts:
    # Preserve existing registered accounts here.
    - configuration:
        connector_id: obsidian
        account_id: null
        subject_id: example-operator # exactly the operator_id above
        credential_ref: null
        policy:
          revision: 1
          consent: explicitly_granted
          retention: encrypted_evidence
          egress: local_only
          agent_authority: denied
          side_effects: forbidden
          limits:
            max_items_per_run: 1000
            max_bytes_per_item: 16777216
            max_total_bytes_per_run: 134217728
            max_runtime_seconds: 300
      lifecycle: active
      lifecycle_revision: 1
```

Stop and restart the daemon after changing `freedom.yaml` so its retained
control-plane projection is rebuilt from the configuration. A missing, paused,
disabled, or non-admitted Obsidian entry keeps the bridge unavailable.

## Install and pair

1. Start `neothd serve` with the configured home.
2. Install the plugin into the chosen desktop vault:

   ```powershell
   neoth obsidian bridge install --vault 'C:/Users/example/Documents/NEOTH-Vault'
   ```

   Use `update` only for its authenticated predecessor. `repair` restores
   known owned plugin files; `uninstall` removes only those files and preserves
   the vault plus plugin settings.
3. Create a pairing payload through the running daemon:

   ```powershell
   neoth --output json obsidian bridge pair --vault 'C:/Users/example/Documents/NEOTH-Vault'
   ```

   Copy the complete JSON result into the Archive Bridge's desktop Obsidian
   command. It contains the local endpoint, pairing secret, protocol, and
   generation. Keep it private: the secret authenticates the scoped local
   plugin channel. It is not a Connector-Control bearer token.
4. Check daemon-owned pairing state without inspecting plugin files:

   ```powershell
   neoth --output json obsidian bridge pairing-status
   ```

The existing `neoth obsidian bridge status --vault …` is different: it reports
the installed plugin artifact in that vault, not the daemon pairing state.

## What the plugin queues

Only Markdown notes below `NEOTH-sessions/` whose frontmatter contains exactly
`source: neoth-archive-bridge` are eligible. The plugin stores up to 128 opaque
descriptors in its private local settings. A descriptor has an event id,
generation, source id, and source revision; it never stores a note body or
filesystem path in the queue.

If the daemon is offline, the queue stays intact for a later manual retry.
The daemon verifies the paired generation and freshly plans the vault note; a
changed or missing note is reported as stale rather than importing an earlier
snapshot. A successful, already-current, or stale result clears only that
matching queued descriptor.

## Revoke a pairing

```powershell
neoth --output json obsidian bridge unpair --vault 'C:/Users/example/Documents/NEOTH-Vault'
```

Unpair advances the pairing generation and makes previously queued plugin work
inert. Pair again to create a fresh payload. Removing or repairing the plugin
does not itself grant or retain daemon import authority.

## Boundaries

- The plugin uses same-user local IPC only; there is no TCP fallback.
- The daemon owns pairing state, policy checks, current-vault planning,
  sanitization, GroundTruth insertion, and receipts.
- Pairing secrets are not printed by status commands and should not be copied
  into issue reports, logs, or shared notes.
