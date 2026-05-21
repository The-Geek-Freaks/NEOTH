# wasm-plugin-hello — minimal NEOTH plugin

Smallest WASM plugin that satisfies the NEOTH plugin ABI. Exports
one function: `neoth_run() -> i32` that returns 0 (success).

## Build

Requires the `wasm32-unknown-unknown` target:

```bash
rustup target add wasm32-unknown-unknown
cargo build --release --target wasm32-unknown-unknown \
  --manifest-path examples/wasm-plugin-hello/Cargo.toml
```

Output: `target/wasm32-unknown-unknown/release/wasm_plugin_hello.wasm`

## Install

Copy the built `.wasm` + this directory's `plugin.toml` into the
operator's plugin dir under the manifest's `id` ("hello"):

```bash
mkdir -p ~/.neoth/plugins/hello
cp target/wasm32-unknown-unknown/release/wasm_plugin_hello.wasm \
   ~/.neoth/plugins/hello/plugin.wasm
cp examples/wasm-plugin-hello/plugin.toml \
   ~/.neoth/plugins/hello/plugin.toml
```

## Verify

```bash
# Discovery + compile pre-flight:
neoth plugins list
# expected: "hello" listed with status=compiled

# After `neoth serve` starts, hook actions targeting plugin_id =
# "hello" fire on every stage match. Example hooks.toml entry:
#   [[hooks]]
#   name = "audit-via-hello"
#   stage = "pre_provider_call"
#   action = { kind = "plugin", plugin_id = "hello" }
```

## Why this exists

Pick #34's daemon-side bootstrap (`cli/serve.rs::bootstrap_plugin_invoker`)
runs the full
```
discover → compile → instantiate → call neoth_run
```
chain. Unit tests cover every step in isolation; this fixture is
the only built artefact that exercises the happy path end-to-end.
