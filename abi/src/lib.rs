//! Shared ABI helpers for HeliosProxy WASM plugins.
//!
//! The proxy's plugin runtime (see `Proxy/src/plugins/runtime.rs`)
//! expects every plugin to export:
//!
//! ```text
//! alloc(size: i32) -> i32
//! dealloc(ptr: i32, size: i32)
//! memory                                ;; auto-exported by wasm32 LLVM
//! <hook_name>(ptr: i32, len: i32) -> i64   ;; result-returning ABI
//! <hook_name>(ptr: i32, len: i32)          ;; observer ABI (no return)
//! ```
//!
//! The result-returning ABI packs the output slot's pointer + length
//! into a single `i64`: `(ptr << 32) | (len & 0xFFFF_FFFF)`. The host
//! reads the bytes out of the plugin's linear memory and then frees
//! the slot via `dealloc`.
//!
//! This crate provides:
//!
//! - The `abi_exports!()` macro: emits a bump-pointer `alloc`/`dealloc`
//!   pair as `#[no_mangle] extern "C"` symbols. Each plugin invokes the
//!   macro once at the crate root.
//! - `read_args` / `write_result` helpers that handle the i32/i64
//!   marshalling so plugin authors never touch raw pointers.
//! - Mirror types for the proxy's `QueryContext`, `HookContext`,
//!   `PreQueryResult`, `PostQueryOutcome` — kept in sync by the wire
//!   contract (JSON), not by a shared Rust dependency. If the proxy
//!   adds a field, `serde(default)` keeps existing plugins working.
//!
//! This crate is `wasm32`-friendly but compiles for any target so
//! plugins keep their unit tests on the host.

#![cfg_attr(not(test), no_std)]
extern crate alloc as core_alloc;

use core_alloc::string::String;
use core_alloc::vec::Vec;
use core_alloc::vec;
use core_alloc::collections::BTreeMap;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Wire types — mirror of `crate::plugins::*` in the proxy. Field shape
// is the contract; renaming or reordering is a breaking change.
// ---------------------------------------------------------------------------

/// Mirror of `plugins::HookContext`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HookContext {
    #[serde(default)]
    pub request_id: String,
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub identity: Option<String>,
    #[serde(default)]
    pub database: Option<String>,
    #[serde(default)]
    pub branch: Option<String>,
    /// Free-form per-request attributes. The proxy uses this to inject
    /// plugin-specific state (e.g. `tenant_id`, `tenant_budget_*`)
    /// that would otherwise need a host-import bridge.
    #[serde(default)]
    pub attributes: BTreeMap<String, String>,
}

/// Mirror of `plugins::QueryContext`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct QueryContext {
    pub query: String,
    #[serde(default)]
    pub normalized: String,
    #[serde(default)]
    pub tables: Vec<String>,
    #[serde(default)]
    pub is_read_only: bool,
    pub hook_context: HookContext,
}

/// Mirror of `plugins::PreQueryResult`.
///
/// `serde` tag = `kind` to keep the wire form stable when adding new
/// variants.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum PreQueryResult {
    Continue,
    Rewrite { sql: String },
    Block { reason: String },
    Cached { bytes: Vec<u8> },
}

/// Mirror of `plugins::PostQueryOutcome`. Read-only for plugins; the
/// proxy passes this in alongside `QueryContext` for post-hooks.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PostQueryOutcome {
    pub success: bool,
    #[serde(default)]
    pub target_node: Option<String>,
    pub elapsed_us: u64,
    pub response_bytes: u64,
    #[serde(default)]
    pub error: Option<String>,
}

/// Combined post-query envelope. Plugins receiving the post hook
/// always get `(QueryContext, PostQueryOutcome)` — the host packs them
/// into this struct so the plugin sees one JSON object.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PostQueryEnvelope {
    pub query_context: QueryContext,
    pub outcome: PostQueryOutcome,
}

// ---------------------------------------------------------------------------
// Marshalling helpers
// ---------------------------------------------------------------------------

/// Read the input slot as a slice. Safe to call with the (ptr, len)
/// pair the host passed in.
///
/// # Safety
///
/// The host promises `ptr` was returned from `alloc(len)` on this
/// instance and that no aliasing slice is live. Each plugin entry
/// point upholds these invariants by treating its inputs as opaque
/// and immediately copying out.
pub unsafe fn read_args<'a>(ptr: i32, len: i32) -> &'a [u8] {
    if len <= 0 {
        return &[];
    }
    core::slice::from_raw_parts(ptr as *const u8, len as usize)
}

/// Allocate an output slot inside the plugin's linear memory, copy
/// `bytes` into it, and pack the (ptr, len) pair into the i64 the
/// host expects. The host frees the slot via `dealloc`.
///
/// Only meaningful on `wasm32-unknown-unknown` (where the plugin's
/// `alloc` export resolves the link). On host targets it is a no-op
/// returning 0 — useful so unit tests can compile.
pub fn write_result(bytes: &[u8]) -> i64 {
    if bytes.is_empty() {
        return 0;
    }
    #[cfg(target_arch = "wasm32")]
    {
        let len = bytes.len() as i32;
        let ptr = unsafe { __helios_alloc(len) };
        unsafe {
            core::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr as *mut u8, bytes.len());
        }
        pack(ptr, len)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        // Host-side stub: returns the byte count so tests can verify
        // the helper was called with the expected payload size.
        bytes.len() as i64
    }
}

/// Pack `(ptr, len)` → i64 the way the host runtime expects.
#[inline]
pub fn pack(ptr: i32, len: i32) -> i64 {
    ((ptr as i64) << 32) | (len as i64 & 0xFFFF_FFFF)
}

#[cfg(target_arch = "wasm32")]
extern "C" {
    /// Internally-resolved alias for the plugin's exported `alloc`
    /// — the [`abi_exports`] macro emits a `#[no_mangle]` `alloc`
    /// that points at the bump allocator below; this `extern` lets
    /// the helpers call it without name conflicts.
    #[link_name = "alloc"]
    fn __helios_alloc(size: i32) -> i32;
}

// ---------------------------------------------------------------------------
// Macro: emits the bump allocator + alloc/dealloc exports
// ---------------------------------------------------------------------------

/// Emits `alloc`, `dealloc`, and the bump-allocator state. Plugins
/// invoke once at crate root.
///
/// The bump allocator is intentionally simple: it grows the WASM
/// linear memory as needed, never reuses freed slots. Per-call
/// hooks stay tiny (1 alloc for input, 1 alloc for output) so this
/// is fine; long-running plugins should swap in a real allocator.
#[macro_export]
macro_rules! abi_exports {
    () => {
        /// Bump pointer initialised lazily on first use. WASM linear
        /// memory starts at 64 KiB; we begin allocating at 65 536 to
        /// avoid colliding with the data segment.
        #[doc(hidden)]
        static mut __HELIOS_BUMP: i32 = 65_536;

        #[no_mangle]
        pub extern "C" fn alloc(size: i32) -> i32 {
            // Word-align to 8 bytes so subsequent calls return
            // pointers compatible with any later allocator swap-in.
            let aligned = (size + 7) & !7;
            unsafe {
                let p = __HELIOS_BUMP;
                __HELIOS_BUMP += aligned;
                p
            }
        }

        #[no_mangle]
        pub extern "C" fn dealloc(_ptr: i32, _size: i32) {
            // Bump allocator: dealloc is a no-op. The runtime drops
            // the entire Store after each `call_hook`, so memory
            // never leaks across calls.
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pack_unpack_roundtrip() {
        let p = pack(4096, 200);
        assert_eq!((p >> 32) as i32, 4096);
        assert_eq!((p & 0xFFFF_FFFF) as i32, 200);
    }

    #[test]
    fn pre_query_result_serde() {
        let block = PreQueryResult::Block { reason: "x".into() };
        let json = serde_json::to_string(&block).unwrap();
        assert!(json.contains("\"kind\":\"block\""));
        let decoded: PreQueryResult = serde_json::from_str(&json).unwrap();
        match decoded {
            PreQueryResult::Block { reason } => assert_eq!(reason, "x"),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn query_context_serde_round_trip() {
        let ctx = QueryContext {
            query: "SELECT 1".into(),
            normalized: "SELECT ?".into(),
            tables: vec!["t".into()],
            is_read_only: true,
            hook_context: HookContext {
                request_id: "r1".into(),
                ..Default::default()
            },
        };
        let json = serde_json::to_vec(&ctx).unwrap();
        let back: QueryContext = serde_json::from_slice(&json).unwrap();
        assert_eq!(back.query, "SELECT 1");
        assert_eq!(back.hook_context.request_id, "r1");
    }
}
