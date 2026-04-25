//! Cost-governor plugin.
//!
//! Tracks per-tenant query cost via a sliding window. Until the proxy
//! exposes its KV namespace as a wasmtime import, the proxy is the
//! source of truth for state: it injects the current per-tenant
//! `usage` and `budget` into `QueryContext.hook_context.attributes`
//! before each call, and writes back the updated usage from the
//! plugin's response.
//!
//! Attribute keys (proxy ⇄ plugin contract):
//!
//! | key                       | direction | value                            |
//! |---------------------------|-----------|----------------------------------|
//! | `tenant_id`               | proxy → plugin | tenant identifier           |
//! | `tenant_usage`            | proxy → plugin | JSON of `TenantUsage`       |
//! | `tenant_budget`           | proxy → plugin | JSON of `TenantBudget`      |
//! | `cost_estimate`           | plugin → proxy (post hook only) | f64 string |
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
use serde::{Deserialize, Serialize};

use helios_plugin_abi::{
    abi_exports, read_args, write_result, PostQueryEnvelope, PreQueryResult, QueryContext,
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

/// Decide whether to allow a query based on the proxy-injected
/// `tenant_usage` / `tenant_budget` attributes. Missing attributes
/// are treated as "no budget configured" → Allow (the proxy will
/// not call us for tenants that didn't opt in).
fn decide_pre_query(ctx: &QueryContext) -> PreQueryResult {
    let attrs = &ctx.hook_context.attributes;

    let usage = attrs
        .get("tenant_usage")
        .and_then(|s| serde_json::from_str::<TenantUsage>(s).ok())
        .unwrap_or_default();
    let budget = attrs
        .get("tenant_budget")
        .and_then(|s| serde_json::from_str::<TenantBudget>(s).ok())
        .unwrap_or_default();

    match check_budget(&usage, &budget) {
        BudgetDecision::Allow => PreQueryResult::Continue,
        BudgetDecision::Block { reason, retry_after_secs } => PreQueryResult::Block {
            reason: format!("{} (retry in {}s)", reason, retry_after_secs),
        },
    }
}

/// Write the post-query observation back to a small JSON payload the
/// proxy can use to update tenant usage. Keeps the cost calc
/// host-checkable.
fn observe_post_query(env: &PostQueryEnvelope) -> CostObservation {
    let rows_estimate = (env.outcome.response_bytes / 64).max(0); // crude: 64-byte avg row
    CostObservation {
        cost: estimate_cost(rows_estimate, env.outcome.elapsed_us / 1000),
        success: env.outcome.success,
        target_node: env.outcome.target_node.clone(),
    }
}

#[derive(Debug, Serialize)]
struct CostObservation {
    cost: f64,
    success: bool,
    target_node: Option<String>,
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

    fn make_ctx(usage: &str, budget: &str) -> QueryContext {
        let mut ctx = QueryContext::default();
        ctx.query = "SELECT 1".to_string();
        ctx.hook_context
            .attributes
            .insert("tenant_id".into(), "t1".into());
        ctx.hook_context
            .attributes
            .insert("tenant_usage".into(), usage.to_string());
        ctx.hook_context
            .attributes
            .insert("tenant_budget".into(), budget.to_string());
        ctx
    }

    #[test]
    fn allows_when_no_budget_configured() {
        let ctx = QueryContext::default();
        match decide_pre_query(&ctx) {
            PreQueryResult::Continue => {}
            other => panic!("expected Continue, got {:?}", other),
        }
    }

    #[test]
    fn allows_under_budget() {
        let ctx = make_ctx(
            r#"{"minute":0.5,"hour":1.0,"day":5.0}"#,
            r#"{"minute":1.0,"hour":10.0,"day":100.0}"#,
        );
        assert!(matches!(decide_pre_query(&ctx), PreQueryResult::Continue));
    }

    #[test]
    fn blocks_on_minute_budget() {
        let ctx = make_ctx(
            r#"{"minute":1.5,"hour":1.5,"day":5.0}"#,
            r#"{"minute":1.0,"hour":10.0,"day":100.0}"#,
        );
        match decide_pre_query(&ctx) {
            PreQueryResult::Block { reason } => {
                assert!(reason.contains("minute"), "got {}", reason);
                assert!(reason.contains("retry in 60s"));
            }
            other => panic!("expected Block, got {:?}", other),
        }
    }

    #[test]
    fn blocks_on_day_overrides_minute() {
        let ctx = make_ctx(
            r#"{"minute":0.0,"hour":0.0,"day":200.0}"#,
            r#"{"minute":1.0,"hour":10.0,"day":100.0}"#,
        );
        match decide_pre_query(&ctx) {
            PreQueryResult::Block { reason } => {
                assert!(reason.contains("daily"));
                assert!(reason.contains("retry in 86400s"));
            }
            other => panic!("expected Block, got {:?}", other),
        }
    }

    #[test]
    fn cost_estimate_matches_model() {
        assert!((estimate_cost(1_000_000, 0) - 1.0).abs() < 1e-9);
        assert!((estimate_cost(0, 1000) - 1.0).abs() < 1e-9);
    }

    #[test]
    fn observe_estimates_from_response_size_and_elapsed() {
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
}
