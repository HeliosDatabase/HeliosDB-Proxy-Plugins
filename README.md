# `heliosdb-proxy-plugins` — first-party WASM plugin registry

Plugins for [HeliosProxy](https://github.com/HeliosDatabase/HeliosDB-Proxy)
shipped as WebAssembly modules. Each plugin is its own crate in this
workspace; `cargo build --release --target wasm32-unknown-unknown` in
any sub-directory produces a single `.wasm` artefact the proxy can load.

## Bundles

| Bundle | Plugins | Purpose |
|---|---|---|
| **AI/RAG** | `ai-classifier`, `token-budget`, `llm-guardrail`, `pgvector-router` | Tag LLM-generated DB traffic, enforce per-agent budgets, reject dangerous patterns, route vector queries. |
| **Compliance** | `column-mask`, `audit-chain`, `residency-router` | Per-role column masking, hash-chained tamper-evident audit log, JWT-region routing. |
| **Cost** | `cost-governor` | Per-tenant query-cost budgets, runaway-query auto-kill, off-peak deferral. |

## Building

```sh
# Install the WASM target.
rustup target add wasm32-unknown-unknown

# Build every plugin in the workspace.
cargo build --release --target wasm32-unknown-unknown

# Outputs land at:
# target/wasm32-unknown-unknown/release/<plugin_name>.wasm
```

Each plugin ships with a `plugin.toml` manifest that the proxy reads at
load time. Drop the `.wasm` and `plugin.toml` into the proxy's
`plugin_dir` (configured in `proxy.toml`) and they're picked up.

## Plugin ABI

The proxy hosts plugins via wasmtime. Each plugin exposes one
exported function per hook it implements:

| Hook | Export name | Signature |
|---|---|---|
| Pre-query | `pre_query` | `(ctx_ptr: i32, ctx_len: i32) -> i64` |
| Post-query | `post_query` | `(payload_ptr: i32, payload_len: i32)` |
| Authenticate | `authenticate` | `(req_ptr: i32, req_len: i32) -> i64` |
| Route | `route` | `(ctx_ptr: i32, ctx_len: i32) -> i64` |
| Rewrite | `rewrite` | `(ctx_ptr: i32, ctx_len: i32) -> i64` |

Where `i64` returns are packed `(result_ptr << 32) | result_len` and
the result bytes are JSON in the proxy's plugin types
(`PreQueryResult`, `AuthResult`, `RouteResult`).

A reference helper crate is planned to abstract the ABI behind a
`#[plugin_hook]` macro — for now plugins use raw `wasm_bindgen`-free
extern "C" exports.

## Status

Plugin sources are skeletons. The actual WASM execution path in the
proxy (`src/plugins/runtime.rs::call_hook`) is currently stubbed; once
wasmtime is wired in proper, the plugins land in order:

1. `cost-governor` (T2.3) — rate-limit composition, simplest.
2. `ai-classifier` (T2.2-P1) — heuristic SQL classifier.
3. `column-mask` (T2.4-P1) — pre-query rewrite.
4. `token-budget` (T2.2-P2) — depends on classifier.
5. `llm-guardrail` (T2.2-P3) — depends on classifier.
6. `pgvector-router` (T2.2-P4) — independent.
7. `audit-chain` (T2.4-P2) — post-query observer with S3.
8. `residency-router` (T2.4-P3) — needs JWT identity from auth hook.
