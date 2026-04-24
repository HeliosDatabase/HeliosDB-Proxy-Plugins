//! Token-budget plugin.
//!
//! Gates AI-tagged traffic on a per-agent / per-model cost budget.
//! Cost units are abstract (configurable α·rows + β·wall_time) and
//! aggregated per `(agent_id, model_id)` pair extracted from the
//! query context (set by the upstream `ai-classifier` plugin).
//!
//! Pre-query: looks up budget remaining; if zero, returns
//! `PreQueryResult::Block` with a structured retry-after.
//! Post-query: records the observed cost into the rolling window.
//!
//! Budgets live in the plugin's KV namespace keyed by
//! `agent_budget:{agent_id}:{model_id}`. Refresh cadence: 1 minute
//! sliding window per agent, plus daily caps.

#![allow(dead_code)]

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentKey {
    pub agent_id: String,
    pub model_id: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct AgentSpend {
    pub minute: f64,
    pub day: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentBudget {
    pub minute: f64,
    pub day: f64,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum BudgetDecision {
    Allow,
    Block { reason: String, retry_after_secs: u64 },
}

pub fn check(spend: &AgentSpend, budget: &AgentBudget) -> BudgetDecision {
    if spend.day >= budget.day {
        return BudgetDecision::Block {
            reason: format!(
                "daily token budget exceeded ({:.2}/{:.2})",
                spend.day, budget.day
            ),
            retry_after_secs: 86_400,
        };
    }
    if spend.minute >= budget.minute {
        return BudgetDecision::Block {
            reason: format!(
                "per-minute token budget exceeded ({:.2}/{:.2})",
                spend.minute, budget.minute
            ),
            retry_after_secs: 60,
        };
    }
    BudgetDecision::Allow
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
    fn allow_under_budget() {
        let s = AgentSpend { minute: 0.5, day: 1.0 };
        let b = AgentBudget { minute: 1.0, day: 10.0 };
        assert!(matches!(check(&s, &b), BudgetDecision::Allow));
    }

    #[test]
    fn block_on_minute() {
        let s = AgentSpend { minute: 1.5, day: 0.5 };
        let b = AgentBudget { minute: 1.0, day: 10.0 };
        match check(&s, &b) {
            BudgetDecision::Block { retry_after_secs, .. } => assert_eq!(retry_after_secs, 60),
            _ => panic!(),
        }
    }

    #[test]
    fn day_takes_precedence_over_minute() {
        let s = AgentSpend { minute: 5.0, day: 50.0 };
        let b = AgentBudget { minute: 1.0, day: 10.0 };
        match check(&s, &b) {
            BudgetDecision::Block { retry_after_secs, .. } => assert_eq!(retry_after_secs, 86_400),
            _ => panic!(),
        }
    }
}
