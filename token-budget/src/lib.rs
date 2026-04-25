//! Token-budget plugin.
//!
//! Gates AI-tagged traffic on a per-`(agent_id, model_id)` cost
//! budget. Cost units are abstract — measured by an upstream
//! classifier (the `ai-classifier` plugin) that tags the query with
//! `agent_id` and `model_id` in `hook_context.attributes`.
//!
//! KV layout (per-plugin namespace `helios-plugin-token-budget`):
//!
//! - `agent:<id>:<model>:spend`  → JSON of [`AgentSpend`]
//! - `agent:<id>:<model>:budget` → JSON of [`AgentBudget`]
//!
//! Pre-query: looks up budget remaining; if exhausted, returns
//! `PreQueryResult::Block` with a structured retry-after.
//! Post-query: increments the rolling window (1-minute + daily caps).
//!
//! The proxy seeds budgets via the operator's `TenantQuota` reconciler
//! writing through the runtime's `kv()` accessor — same out-of-band
//! seeding mechanism as cost-governor.

#![cfg_attr(not(test), no_std)]
extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

use helios_plugin_abi::{
    abi_exports, kv_read, kv_write, read_args, write_result, PostQueryEnvelope,
    PreQueryResult, QueryContext,
};

abi_exports!();

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AgentSpend {
    pub minute: f64,
    pub day: f64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AgentBudget {
    pub minute: f64,
    pub day: f64,
}

#[derive(Debug, Clone)]
pub enum BudgetDecision {
    Allow,
    Block { reason: String, retry_after_secs: u64 },
}

pub fn check(spend: &AgentSpend, budget: &AgentBudget) -> BudgetDecision {
    if budget.day > 0.0 && spend.day >= budget.day {
        return BudgetDecision::Block {
            reason: format!(
                "daily token budget exceeded ({:.2}/{:.2})",
                spend.day, budget.day
            ),
            retry_after_secs: 86_400,
        };
    }
    if budget.minute > 0.0 && spend.minute >= budget.minute {
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

fn agent_key(ctx: &QueryContext) -> Option<(String, String)> {
    let agent = ctx.hook_context.attributes.get("agent_id")?.clone();
    let model = ctx.hook_context.attributes.get("model_id")?.clone();
    Some((agent, model))
}

fn key_spend(agent: &str, model: &str) -> Vec<u8> {
    format!("agent:{}:{}:spend", agent, model).into_bytes()
}

fn key_budget(agent: &str, model: &str) -> Vec<u8> {
    format!("agent:{}:{}:budget", agent, model).into_bytes()
}

pub fn decide_pre_query(ctx: &QueryContext) -> PreQueryResult {
    let Some((agent, model)) = agent_key(ctx) else {
        // No AI tag — not our traffic. Pass.
        return PreQueryResult::Continue;
    };
    let spend: AgentSpend = kv_read(&key_spend(&agent, &model))
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default();
    let budget: AgentBudget = match kv_read(&key_budget(&agent, &model))
        .and_then(|b| serde_json::from_slice(&b).ok())
    {
        Some(b) => b,
        None => return PreQueryResult::Continue, // no budget configured
    };
    match check(&spend, &budget) {
        BudgetDecision::Allow => PreQueryResult::Continue,
        BudgetDecision::Block { reason, retry_after_secs } => PreQueryResult::Block {
            reason: format!("{} (retry in {}s)", reason, retry_after_secs),
        },
    }
}

/// Token-cost model:
///   tokens ≈ response_bytes / 4   (LLM response ≈ 4 bytes per token)
///   cost   = tokens × 1e-3        (configurable per-model in future)
pub fn estimate_token_cost(response_bytes: u64) -> f64 {
    let tokens = (response_bytes as f64) / 4.0;
    tokens * 1e-3
}

pub fn observe_post_query(env: &PostQueryEnvelope) -> TokenObservation {
    let cost = estimate_token_cost(env.outcome.response_bytes);
    if let Some((agent, model)) = agent_key(&env.query_context) {
        let mut spend: AgentSpend = kv_read(&key_spend(&agent, &model))
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        spend.minute += cost;
        spend.day += cost;
        if let Ok(bytes) = serde_json::to_vec(&spend) {
            kv_write(&key_spend(&agent, &model), &bytes);
        }
    }
    TokenObservation { cost, success: env.outcome.success }
}

#[derive(Debug, Serialize)]
pub struct TokenObservation {
    pub cost: f64,
    pub success: bool,
}

// ---------------------------------------------------------------------------
// WASM exports
// ---------------------------------------------------------------------------

#[no_mangle]
pub extern "C" fn pre_query(ptr: i32, len: i32) -> i64 {
    let bytes = unsafe { read_args(ptr, len) };
    let ctx: QueryContext = match serde_json::from_slice(bytes) {
        Ok(c) => c,
        Err(_) => return 0,
    };
    let decision = decide_pre_query(&ctx);
    let bytes = serde_json::to_vec(&decision).unwrap_or_default();
    write_result(&bytes)
}

#[no_mangle]
pub extern "C" fn post_query(ptr: i32, len: i32) -> i64 {
    let bytes = unsafe { read_args(ptr, len) };
    let env: PostQueryEnvelope = match serde_json::from_slice(bytes) {
        Ok(e) => e,
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
            BudgetDecision::Block { retry_after_secs, reason } => {
                assert_eq!(retry_after_secs, 60);
                assert!(reason.contains("minute"));
            }
            BudgetDecision::Allow => panic!("expected minute Block"),
        }
    }

    #[test]
    fn day_takes_precedence_over_minute() {
        let s = AgentSpend { minute: 5.0, day: 50.0 };
        let b = AgentBudget { minute: 1.0, day: 10.0 };
        match check(&s, &b) {
            BudgetDecision::Block { retry_after_secs, reason } => {
                assert_eq!(retry_after_secs, 86_400);
                assert!(reason.contains("daily"));
            }
            BudgetDecision::Allow => panic!("expected daily Block"),
        }
    }

    #[test]
    fn untagged_query_is_passed_through() {
        let ctx = QueryContext::default();
        match decide_pre_query(&ctx) {
            PreQueryResult::Continue => {}
            other => panic!("expected Continue, got {:?}", other),
        }
    }

    #[test]
    fn missing_budget_allows_tagged_query() {
        // Agent + model tagged, but no budget seeded.
        let mut ctx = QueryContext::default();
        ctx.hook_context
            .attributes
            .insert("agent_id".into(), "rag-bot".into());
        ctx.hook_context
            .attributes
            .insert("model_id".into(), "claude-opus-4-7".into());
        match decide_pre_query(&ctx) {
            PreQueryResult::Continue => {}
            other => panic!("expected Continue, got {:?}", other),
        }
    }

    #[test]
    fn key_format_includes_agent_and_model() {
        assert_eq!(key_spend("rag-bot", "claude"), b"agent:rag-bot:claude:spend");
        assert_eq!(key_budget("rag-bot", "claude"), b"agent:rag-bot:claude:budget");
    }

    #[test]
    fn token_cost_at_4_bytes_per_token() {
        assert!((estimate_token_cost(4_000) - 1.0).abs() < 1e-9);
        assert!((estimate_token_cost(0) - 0.0).abs() < 1e-9);
    }
}
