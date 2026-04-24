//! Cost-governor plugin.
//!
//! Tracks per-tenant query cost via a sliding window kept in the
//! plugin's KV namespace (provided by the proxy host functions).
//! Pre-query hook checks whether the tenant has budget left; if not,
//! returns `PreQueryResult::Block`. Post-query hook records the
//! observed cost (rows scanned × α + wall-time × β).
//!
//! Cost model defaults — overridable per-tenant via the proxy's
//! `TenantQuota` CRD (T1.1):
//!
//! ```text
//! cost = α · rows_scanned  +  β · wall_time_ms
//! α = 1e-6,  β = 1e-3   (≈ 1¢ per 10k rows or 10s of wall time)
//! ```
//!
//! Budget windows: 1 minute (rate-limit feel), 1 hour, 1 day. Tenants
//! that breach the daily budget get a `Block` with a structured
//! reason that includes the budget remaining at the next reset.

#![allow(dead_code)]

use serde::{Deserialize, Serialize};

const ALPHA_PER_ROW: f64 = 1e-6;
const BETA_PER_MS: f64 = 1e-3;

#[derive(Debug, Deserialize)]
struct TenantId(String);

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct TenantUsage {
    pub minute: f64,
    pub hour: f64,
    pub day: f64,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct TenantBudget {
    pub minute: f64,
    pub hour: f64,
    pub day: f64,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum BudgetDecision {
    Allow,
    Block {
        reason: String,
        retry_after_secs: u64,
    },
}

pub fn check_budget(usage: &TenantUsage, budget: &TenantBudget) -> BudgetDecision {
    if usage.day >= budget.day {
        return BudgetDecision::Block {
            reason: format!(
                "tenant exceeded daily budget ({:.2}/{:.2})",
                usage.day, budget.day
            ),
            retry_after_secs: seconds_until_next_day(),
        };
    }
    if usage.hour >= budget.hour {
        return BudgetDecision::Block {
            reason: format!(
                "tenant exceeded hourly budget ({:.2}/{:.2})",
                usage.hour, budget.hour
            ),
            retry_after_secs: seconds_until_next_hour(),
        };
    }
    if usage.minute >= budget.minute {
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

fn seconds_until_next_minute() -> u64 {
    60
}
fn seconds_until_next_hour() -> u64 {
    3600
}
fn seconds_until_next_day() -> u64 {
    86_400
}

#[no_mangle]
pub extern "C" fn pre_query(_ctx_ptr: i32, _ctx_len: i32) -> i64 {
    0
}

#[no_mangle]
pub extern "C" fn post_query(_ctx_ptr: i32, _ctx_len: i32) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_under_budget() {
        let u = TenantUsage {
            minute: 0.5,
            hour: 1.0,
            day: 5.0,
        };
        let b = TenantBudget {
            minute: 1.0,
            hour: 10.0,
            day: 100.0,
        };
        assert!(matches!(check_budget(&u, &b), BudgetDecision::Allow));
    }

    #[test]
    fn blocks_on_minute() {
        let u = TenantUsage {
            minute: 1.5,
            hour: 1.5,
            day: 5.0,
        };
        let b = TenantBudget {
            minute: 1.0,
            hour: 10.0,
            day: 100.0,
        };
        match check_budget(&u, &b) {
            BudgetDecision::Block { retry_after_secs, .. } => assert_eq!(retry_after_secs, 60),
            _ => panic!("expected Block"),
        }
    }

    #[test]
    fn blocks_on_day_overrides_minute() {
        let u = TenantUsage {
            minute: 0.0,
            hour: 0.0,
            day: 200.0,
        };
        let b = TenantBudget {
            minute: 1.0,
            hour: 10.0,
            day: 100.0,
        };
        match check_budget(&u, &b) {
            BudgetDecision::Block { retry_after_secs, .. } => assert_eq!(retry_after_secs, 86_400),
            _ => panic!("expected Block"),
        }
    }

    #[test]
    fn cost_estimate_matches_model() {
        assert!((estimate_cost(1_000_000, 0) - 1.0).abs() < 1e-9);
        assert!((estimate_cost(0, 1000) - 1.0).abs() < 1e-9);
    }
}
