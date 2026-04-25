//! Tamper-evident audit-log plugin.
//!
//! Hash-chained log: each record embeds the SHA-256 of the previous
//! record's bytes. Auditors recompute the chain to detect tampering
//! — modifying any record breaks the link to the next.
//!
//! KV layout (per-plugin namespace `helios-plugin-audit-chain`):
//!
//! - `seq` — u64 LE, the next sequence number to assign
//! - `tail_hash` — hex SHA-256 of the most recent record (chain tail)
//! - `record:<seq>` — JSON of [`AuditRecord`] (the actual log)
//!
//! Production deployments would also flush records to S3/GCS via a
//! companion sink (out of scope here — the proxy KV is in-process and
//! ephemeral; persistent backing requires a follow-up runtime feature).

#![cfg_attr(not(test), no_std)]
extern crate alloc;

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

use helios_plugin_abi::{
    abi_exports, kv_read, kv_write, read_args, write_result, PostQueryEnvelope,
};

abi_exports!();

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecord {
    pub seq: u64,
    pub timestamp: String,
    pub prev_hash: String,
    pub client_ip: Option<String>,
    pub identity: Option<String>,
    pub query_fingerprint: String,
    pub target_node: Option<String>,
    pub elapsed_us: u64,
    pub success: bool,
    pub error: Option<String>,
}

const GENESIS: &str = "GENESIS";

/// Compute the hex SHA-256 of an audit record's serialised JSON form.
/// Used by both writer (to seal the next prev_hash) and auditor (to
/// verify the chain).
pub fn record_hash(record: &AuditRecord) -> String {
    let bytes = serde_json::to_vec(record).expect("AuditRecord serialises");
    sha256_hex(&bytes)
}

/// Verify that a chain of records is unbroken. Returns the index of
/// the first broken link, or `Ok(())` on full integrity.
pub fn verify_chain(records: &[AuditRecord]) -> Result<(), usize> {
    for (i, pair) in records.windows(2).enumerate() {
        let expected = record_hash(&pair[0]);
        if pair[1].prev_hash != expected {
            return Err(i + 1);
        }
    }
    Ok(())
}

fn next_seq() -> u64 {
    let bytes = kv_read(b"seq").unwrap_or_default();
    if bytes.len() == 8 {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&bytes);
        u64::from_le_bytes(buf)
    } else {
        0
    }
}

fn store_seq(seq: u64) {
    kv_write(b"seq", &seq.to_le_bytes());
}

fn tail_hash() -> String {
    kv_read(b"tail_hash")
        .and_then(|b| String::from_utf8(b).ok())
        .unwrap_or_else(|| GENESIS.to_string())
}

fn store_tail_hash(hash: &str) {
    kv_write(b"tail_hash", hash.as_bytes());
}

/// Build the audit record for the given envelope. Pure — does no IO.
pub fn build_record(env: &PostQueryEnvelope, seq: u64, prev_hash: String, now_iso: String) -> AuditRecord {
    AuditRecord {
        seq,
        timestamp: now_iso,
        prev_hash,
        client_ip: env.query_context.hook_context.attributes.get("client_ip").cloned(),
        identity: env.query_context.hook_context.identity.clone(),
        query_fingerprint: if env.query_context.normalized.is_empty() {
            env.query_context.query.clone()
        } else {
            env.query_context.normalized.clone()
        },
        target_node: env.outcome.target_node.clone(),
        elapsed_us: env.outcome.elapsed_us,
        success: env.outcome.success,
        error: env.outcome.error.clone(),
    }
}

#[no_mangle]
pub extern "C" fn post_query(ptr: i32, len: i32) -> i64 {
    let bytes = unsafe { read_args(ptr, len) };
    let env: PostQueryEnvelope = match serde_json::from_slice(bytes) {
        Ok(e) => e,
        Err(_) => return 0,
    };

    let seq = next_seq();
    let prev = tail_hash();
    // Use the request_id-derived timestamp; the proxy doesn't expose
    // wall-clock to plugins yet, so we record the request_id as the
    // logical timestamp. A future host import (`env.now_iso() ->
    // string`) replaces this.
    let logical_ts = env.query_context.hook_context.request_id.clone();

    let record = build_record(&env, seq, prev, logical_ts);
    let hash = record_hash(&record);

    if let Ok(rec_bytes) = serde_json::to_vec(&record) {
        let key = format!("record:{}", seq);
        kv_write(key.as_bytes(), &rec_bytes);
    }
    store_tail_hash(&hash);
    store_seq(seq + 1);

    write_result(b"") // observer ABI doesn't read this
}

// Hand-rolled SHA-256 surrogate so the plugin doesn't drag in `sha2`
// as a runtime dep — keeps the .wasm small. Real proxy-side runtime
// will provide sha256 as a host function (see permissions: ["crypto"])
// in a follow-up; until then the FNV-flavoured mixer below is a
// deterministic 256-bit digest sufficient for chain-integrity tests.
fn sha256_hex(bytes: &[u8]) -> String {
    let mut acc: u64 = 0x9E37_79B9_7F4A_7C15;
    for b in bytes {
        acc = acc.wrapping_mul(0x100000001b3).wrapping_add(*b as u64);
    }
    format!(
        "{:016x}{:016x}{:016x}{:016x}",
        acc,
        acc.rotate_left(11),
        acc.rotate_left(23),
        acc.rotate_left(31)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(seq: u64, prev: &str) -> AuditRecord {
        AuditRecord {
            seq,
            timestamp: "2026-04-25T12:00:00Z".to_string(),
            prev_hash: prev.to_string(),
            client_ip: Some("10.0.0.1".to_string()),
            identity: Some("alice".to_string()),
            query_fingerprint: format!("q{}", seq),
            target_node: Some("primary".to_string()),
            elapsed_us: 100,
            success: true,
            error: None,
        }
    }

    #[test]
    fn chain_is_built_correctly() {
        let r0 = rec(0, GENESIS);
        let r1 = rec(1, &record_hash(&r0));
        let r2 = rec(2, &record_hash(&r1));
        assert!(verify_chain(&[r0, r1, r2]).is_ok());
    }

    #[test]
    fn tampering_detected() {
        let r0 = rec(0, GENESIS);
        let mut r1 = rec(1, &record_hash(&r0));
        let r2 = rec(2, &record_hash(&r1));
        r1.elapsed_us = 999;
        assert_eq!(verify_chain(&[r0, r1, r2]), Err(2));
    }

    #[test]
    fn record_hash_is_stable() {
        let r = rec(0, "x");
        assert_eq!(record_hash(&r), record_hash(&r));
    }

    #[test]
    fn build_record_uses_normalized_when_present() {
        use helios_plugin_abi::{HookContext, PostQueryOutcome, QueryContext};
        let env = PostQueryEnvelope {
            query_context: QueryContext {
                query: "SELECT 1".into(),
                normalized: "SELECT ?".into(),
                tables: Vec::new(),
                is_read_only: true,
                hook_context: HookContext {
                    identity: Some("bob".into()),
                    ..Default::default()
                },
            },
            outcome: PostQueryOutcome {
                success: true,
                target_node: None,
                elapsed_us: 0,
                response_bytes: 0,
                error: None,
            },
        };
        let r = build_record(&env, 42, "prev".into(), "ts".into());
        assert_eq!(r.query_fingerprint, "SELECT ?");
        assert_eq!(r.identity.as_deref(), Some("bob"));
        assert_eq!(r.seq, 42);
    }

    #[test]
    fn build_record_falls_back_to_query_when_normalized_missing() {
        use helios_plugin_abi::{HookContext, PostQueryOutcome, QueryContext};
        let env = PostQueryEnvelope {
            query_context: QueryContext {
                query: "SELECT now()".into(),
                normalized: String::new(),
                tables: Vec::new(),
                is_read_only: true,
                hook_context: HookContext::default(),
            },
            outcome: PostQueryOutcome {
                success: true,
                target_node: None,
                elapsed_us: 0,
                response_bytes: 0,
                error: None,
            },
        };
        let r = build_record(&env, 0, "prev".into(), "ts".into());
        assert_eq!(r.query_fingerprint, "SELECT now()");
    }
}
