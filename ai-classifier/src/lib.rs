//! AI-traffic classifier plugin.
//!
//! Detects LLM-generated SQL via syntactic heuristics + explicit hints
//! (application_name, session var, generated-by markers). The
//! classifier uses the proxy's `Rewrite` hook return path to surface
//! its decision: a positive match returns `PreQueryResult::Block` is
//! NOT what we want — we want the query to flow through, so the
//! classifier writes its findings to the host KV (so downstream
//! plugins can read them) and returns `Continue`.
//!
//! KV layout (per-plugin namespace `helios-plugin-ai-classifier`):
//!
//! - `req:<request_id>:ai_traffic`  → `"true"` or absent
//! - `req:<request_id>:agent_id`    → agent identifier (best guess)
//! - `req:<request_id>:model_id`    → model identifier (best guess)
//!
//! Downstream plugins (`token-budget`, `llm-guardrail`) read the
//! classifier's keys via the same per-request_id pattern. The proxy
//! garbage-collects expired KV entries (out of scope for this slice
//! — for now keys accumulate; first iteration of the proxy KV
//! lifecycle adds TTL support).
//!
//! Heuristics — any of these flips the bit:
//! 1. `application_name` contains `gpt`, `claude`, `gemini`, `llm`,
//!    `chatbot`, `agent`, `openai`, `anthropic` (case-insensitive).
//! 2. SQL contains a generated-by marker (`/* generated`,
//!    `-- generated`, `-- gpt-`, `/* by ai`).
//! 3. Session variable `helios.ai_traffic` set to `true`.

#![cfg_attr(not(test), no_std)]
extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

use helios_plugin_abi::{
    abi_exports, kv_write, read_args, write_result, PreQueryResult, QueryContext,
};

abi_exports!();

const HINT_KEYWORDS: &[&str] = &[
    "gpt", "claude", "gemini", "llm", "chatbot", "agent", "openai", "anthropic",
];

const GENERATED_MARKERS: &[&str] = &[
    "/* generated", "-- generated", "-- gpt-", "/* by ai", "-- by claude",
];

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClassifyResult {
    pub ai_traffic: bool,
    pub agent_id: Option<String>,
    pub model_id: Option<String>,
}

/// Pure-function classifier — covered by unit tests so the heuristics
/// can evolve without re-running a full proxy.
pub fn classify(ctx: &QueryContext) -> ClassifyResult {
    let q = ctx.query.to_lowercase();
    let attrs = &ctx.hook_context.attributes;

    let mut ai_traffic = false;
    let mut agent_id = None;
    let mut model_id = None;

    if let Some(app) = attrs.get("application_name") {
        let lower = app.to_lowercase();
        for kw in HINT_KEYWORDS {
            if lower.contains(kw) {
                ai_traffic = true;
                agent_id = Some(app.clone());
                model_id = guess_model(&lower);
                break;
            }
        }
    }

    if !ai_traffic
        && attrs
            .get("helios.ai_traffic")
            .map(|s| s == "true")
            .unwrap_or(false)
    {
        ai_traffic = true;
        // Explicit opt-in — agent/model come from companion attrs.
        if let Some(a) = attrs.get("helios.agent_id") {
            agent_id = Some(a.clone());
        }
        if let Some(m) = attrs.get("helios.model_id") {
            model_id = Some(m.clone());
        }
    }

    if !ai_traffic && GENERATED_MARKERS.iter().any(|m| q.contains(m)) {
        ai_traffic = true;
        model_id = guess_model(&q);
    }

    ClassifyResult { ai_traffic, agent_id, model_id }
}

/// Best-effort model guess from a lowered string. Returns the first
/// known model substring.
fn guess_model(s: &str) -> Option<String> {
    const MODELS: &[&str] = &[
        "claude-opus", "claude-sonnet", "claude-haiku",
        "gpt-4", "gpt-3.5",
        "gemini",
    ];
    for m in MODELS {
        if s.contains(m) {
            return Some((*m).into());
        }
    }
    None
}

fn req_key(request_id: &str, suffix: &str) -> Vec<u8> {
    format!("req:{}:{}", request_id, suffix).into_bytes()
}

#[no_mangle]
pub extern "C" fn pre_query(ptr: i32, len: i32) -> i64 {
    let bytes = unsafe { read_args(ptr, len) };
    let ctx: QueryContext = match serde_json::from_slice(bytes) {
        Ok(c) => c,
        Err(_) => return 0,
    };
    let result = classify(&ctx);

    // Persist per-request so downstream plugins can read it. We don't
    // mutate QueryContext.attributes in flight because the host
    // doesn't currently round-trip plugin-side mutations back into
    // the live HookContext.
    let req_id = &ctx.hook_context.request_id;
    if result.ai_traffic {
        kv_write(&req_key(req_id, "ai_traffic"), b"true");
    }
    if let Some(a) = &result.agent_id {
        kv_write(&req_key(req_id, "agent_id"), a.as_bytes());
    }
    if let Some(m) = &result.model_id {
        kv_write(&req_key(req_id, "model_id"), m.as_bytes());
    }

    let out = serde_json::to_vec(&PreQueryResult::Continue).unwrap_or_default();
    write_result(&out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx_for(query: &str, attrs: &[(&str, &str)]) -> QueryContext {
        let mut c = QueryContext::default();
        c.query = query.into();
        for (k, v) in attrs {
            c.hook_context
                .attributes
                .insert((*k).into(), (*v).into());
        }
        c
    }

    #[test]
    fn detects_gpt_app_name() {
        let r = classify(&ctx_for("SELECT 1", &[("application_name", "gpt-shopper")]));
        assert!(r.ai_traffic);
        assert_eq!(r.agent_id.as_deref(), Some("gpt-shopper"));
    }

    #[test]
    fn detects_claude_app_name_and_extracts_model() {
        let r = classify(&ctx_for(
            "SELECT 1",
            &[("application_name", "ClaudeAgent-claude-opus-4-7")],
        ));
        assert!(r.ai_traffic);
        assert_eq!(r.model_id.as_deref(), Some("claude-opus"));
    }

    #[test]
    fn detects_explicit_session_opt_in() {
        let r = classify(&ctx_for(
            "SELECT 1",
            &[
                ("helios.ai_traffic", "true"),
                ("helios.agent_id", "rag-bot-v2"),
                ("helios.model_id", "gpt-4"),
            ],
        ));
        assert!(r.ai_traffic);
        assert_eq!(r.agent_id.as_deref(), Some("rag-bot-v2"));
        assert_eq!(r.model_id.as_deref(), Some("gpt-4"));
    }

    #[test]
    fn detects_generated_marker_in_sql() {
        let r = classify(&ctx_for(
            "/* generated by GPT-4 */ SELECT * FROM users",
            &[],
        ));
        assert!(r.ai_traffic);
        // Marker matched, model guessed from the SQL itself.
        assert_eq!(r.model_id.as_deref(), Some("gpt-4"));
    }

    #[test]
    fn ignores_human_traffic() {
        let r = classify(&ctx_for(
            "SELECT id FROM users WHERE id = 1",
            &[("application_name", "psql")],
        ));
        assert!(!r.ai_traffic);
        assert!(r.agent_id.is_none());
    }

    #[test]
    fn req_key_includes_request_id_and_suffix() {
        assert_eq!(req_key("r-123", "ai_traffic"), b"req:r-123:ai_traffic");
    }
}
