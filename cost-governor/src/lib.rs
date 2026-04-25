//! Cost-governor plugin.
//!
//! Tracks per-tenant query cost via a sliding window stored in the
//! host's KV namespace (bridged from the proxy via wasmtime imports
//! in `Proxy/src/plugins/host_imports.rs`).
//!
//! KV layout (per-plugin namespace `helios-plugin-cost-governor`):
//!
//! - `tenant:<id>:usage`  → JSON of [`TenantUsage`]
//! - `tenant:<id>:budget` → JSON of [`TenantBudget`]
//!
//! Usage flow per query:
//!
//! 1. `pre_query` reads `usage` + `budget` for the tenant; if the
//!    daily/hourly/minute window is exhausted, returns
//!    [`PreQueryResult::Block`].
//! 2. `post_query` estimates the query's cost from
//!    `(rows_estimate × α + wall_time_ms × β)` and writes the updated
//!    `usage` back via `kv_write`.
//!
//! Budgets are seeded by the proxy admin layer (out-of-band): the
//! operator's `TenantQuota` CRD reconciler writes the per-tenant
//! `tenant:<id>:budget` into the plugin's KV namespace before any
//! traffic for that tenant arrives.
//!
//! Cost model:
//!
//! ```text
//! cost = α · rows_scanned  +  β · wall_time_ms
//! α = 1e-6,  β = 1e-3   (≈ 1¢ per 10k rows or 10s of wall time)
//! ```

#![cfg_attr(not(test), no_std)]
extern crate alloc;

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

use helios_plugin_abi::{
    abi_exports, kv_read, kv_write, read_args, write_result, PostQueryEnvelope,
    PreQueryResult, QueryContext,
};

abi_exports!();

const ALPHA_PER_ROW: f64 = 1e-6;
const BETA_PER_MS: f64 = 1e-3;

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct TenantUsage {
    pub minute: f64,
    pub hour: f64,
    pub day: f64,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct TenantBudget {
    pub minute: f64,
    pub hour: f64,
    pub day: f64,
}

#[derive(Debug, Clone)]
pub enum BudgetDecision {
    Allow,
    Block { reason: String, retry_after_secs: u64 },
}

pub fn check_budget(usage: &TenantUsage, budget: &TenantBudget) -> BudgetDecision {
    if budget.day > 0.0 && usage.day >= budget.day {
        return BudgetDecision::Block {
            reason: format!(
                "tenant exceeded daily budget ({:.2}/{:.2})",
                usage.day, budget.day
            ),
            retry_after_secs: 86_400,
        };
    }
    if budget.hour > 0.0 && usage.hour >= budget.hour {
        return BudgetDecision::Block {
            reason: format!(
                "tenant exceeded hourly budget ({:.2}/{:.2})",
                usage.hour, budget.hour
            ),
            retry_after_secs: 3_600,
        };
    }
    if budget.minute > 0.0 && usage.minute >= budget.minute {
        return BudgetDecision::Block {
            reason: format!(
                "tenant exceeded minute budget ({:.2}/{:.2})",
                usage.minute, budget.minute
            ),
            retry_after_secs: 60,
        };
    }
    BudgetDecision::Allow
}

pub fn estimate_cost(rows_scanned: u64, wall_time_ms: u64) -> f64 {
    rows_scanned as f64 * ALPHA_PER_ROW + wall_time_ms as f64 * BETA_PER_MS
}

fn tenant_id_from(ctx: &QueryContext) -> Option<&str> {
    ctx.hook_context.attributes.get("tenant_id").map(|s| s.as_str())
}

fn key_usage(tenant: &str) -> Vec<u8> {
    format!("tenant:{}:usage", tenant).into_bytes()
}

fn key_budget(tenant: &str) -> Vec<u8> {
    format!("tenant:{}:budget", tenant).into_bytes()
}

/// Decide whether to allow a query based on the tenant's KV-stored
/// usage + budget. Missing usage ⇒ zero. Missing budget ⇒ Allow
/// (tenant didn't opt in to cost governance).
pub fn decide_pre_query(ctx: &QueryContext) -> PreQueryResult {
    let Some(tenant) = tenant_id_from(ctx) else {
        return PreQueryResult::Continue;
    };
    let usage: TenantUsage = kv_read(&key_usage(tenant))
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default();
    let budget: TenantBudget = match kv_read(&key_budget(tenant))
        .and_then(|b| serde_json::from_slice(&b).ok())
    {
        Some(b) => b,
        None => return PreQueryResult::Continue,
    };
    match check_budget(&usage, &budget) {
        BudgetDecision::Allow => PreQueryResult::Continue,
        BudgetDecision::Block { reason, retry_after_secs } => PreQueryResult::Block {
            reason: format!("{} (retry in {}s)", reason, retry_after_secs),
        },
    }
}

/// Compute the query's cost from the post-query envelope, add it to
/// the tenant's running window, persist, and return a small
/// observation the proxy can ship to metrics.
pub fn observe_post_query(env: &PostQueryEnvelope) -> CostObservation {
    let rows_estimate = env.outcome.response_bytes / 64; // ~64 b/row heuristic
    let cost = estimate_cost(rows_estimate, env.outcome.elapsed_us / 1000);

    if let Some(tenant) = tenant_id_from(&env.query_context) {
        let mut usage: TenantUsage = kv_read(&key_usage(tenant))
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        usage.minute += cost;
        usage.hour += cost;
        usage.day += cost;
        if let Ok(bytes) = serde_json::to_vec(&usage) {
            kv_write(&key_usage(tenant), &bytes);
        }
    }

    CostObservation {
        cost,
        success: env.outcome.success,
        target_node: env.outcome.target_node.clone(),
    }
}

#[derive(Debug, Serialize)]
pub struct CostObservation {
    pub cost: f64,
    pub success: bool,
    pub target_node: Option<String>,
}

// ---------------------------------------------------------------------------
// WASM exports
// ---------------------------------------------------------------------------

#[no_mangle]
pub extern "C" fn pre_query(ptr: i32, len: i32) -> i64 {
    let bytes = unsafe { read_args(ptr, len) };
    let ctx: QueryContext = match serde_json::from_slice(bytes) {
        Ok(c) => c,
        Err(e) => {
            return write_result(
                serde_json::to_vec(&PreQueryResult::Block {
                    reason: format!("cost-governor: invalid QueryContext: {}", e),
                })
                .unwrap_or_default()
                .as_slice(),
            )
        }
    };
    let decision = decide_pre_query(&ctx);
    let bytes = serde_json::to_vec(&decision).unwrap_or_default();
    write_result(&bytes)
}

#[no_mangle]
pub extern "C" fn post_query(ptr: i32, len: i32) -> i64 {
    let bytes = unsafe { read_args(ptr, len) };
    let env: PostQueryEnvelope = match serde_json::from_slice(bytes) {
        Ok(c) => c,
        Err(_) => return 0,
    };
    let obs = observe_post_query(&env);
    let out = serde_json::to_vec(&obs).unwrap_or_default();
    write_result(&out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_when_no_tenant_id() {
        let ctx = QueryContext::default();
        match decide_pre_query(&ctx) {
            PreQueryResult::Continue => {}
            other => panic!("expected Continue, got {:?}", other),
        }
    }

    #[test]
    fn allows_when_no_budget_seeded() {
        // tenant_id present, but kv_read returns None (host stub).
        let mut ctx = QueryContext::default();
        ctx.hook_context
            .attributes
            .insert("tenant_id".into(), "t1".into());
        match decide_pre_query(&ctx) {
            PreQueryResult::Continue => {}
            other => panic!("expected Continue (missing budget ⇒ allow), got {:?}", other),
        }
    }

    #[test]
    fn check_budget_allows_under_threshold() {
        let u = TenantUsage { minute: 0.5, hour: 1.0, day: 5.0 };
        let b = TenantBudget { minute: 1.0, hour: 10.0, day: 100.0 };
        match check_budget(&u, &b) {
            BudgetDecision::Allow => {}
            BudgetDecision::Block { reason, .. } => panic!("unexpected Block: {}", reason),
        }
    }

    #[test]
    fn check_budget_blocks_minute() {
        let u = TenantUsage { minute: 1.5, hour: 1.5, day: 5.0 };
        let b = TenantBudget { minute: 1.0, hour: 10.0, day: 100.0 };
        match check_budget(&u, &b) {
            BudgetDecision::Block { retry_after_secs, reason } => {
                assert_eq!(retry_after_secs, 60);
                assert!(reason.contains("minute"));
            }
            BudgetDecision::Allow => panic!("expected minute Block, got Allow"),
        }
    }

    #[test]
    fn check_budget_day_takes_precedence_over_minute() {
        let u = TenantUsage { minute: 0.0, hour: 0.0, day: 200.0 };
        let b = TenantBudget { minute: 1.0, hour: 10.0, day: 100.0 };
        match check_budget(&u, &b) {
            BudgetDecision::Block { retry_after_secs, reason } => {
                assert_eq!(retry_after_secs, 86_400);
                assert!(reason.contains("daily"));
            }
            BudgetDecision::Allow => panic!("expected daily Block"),
        }
    }

    #[test]
    fn cost_estimate_matches_model() {
        assert!((estimate_cost(1_000_000, 0) - 1.0).abs() < 1e-9);
        assert!((estimate_cost(0, 1000) - 1.0).abs() < 1e-9);
    }

    #[test]
    fn observe_returns_estimated_cost_from_envelope() {
        let env = PostQueryEnvelope {
            query_context: QueryContext::default(),
            outcome: helios_plugin_abi::PostQueryOutcome {
                success: true,
                target_node: Some("primary".into()),
                elapsed_us: 2_000_000, // 2 s = 2000 ms
                response_bytes: 64_000, // ≈ 1000 rows at 64 b avg
                error: None,
            },
        };
        let obs = observe_post_query(&env);
        // 1000 rows × 1e-6 + 2000 ms × 1e-3 = 0.001 + 2.0 ≈ 2.001
        assert!((obs.cost - 2.001).abs() < 1e-3);
        assert!(obs.success);
        assert_eq!(obs.target_node.as_deref(), Some("primary"));
    }

    #[test]
    fn key_format_is_namespaced_per_tenant() {
        assert_eq!(key_usage("acme"), b"tenant:acme:usage");
        assert_eq!(key_budget("acme"), b"tenant:acme:budget");
    }
}
