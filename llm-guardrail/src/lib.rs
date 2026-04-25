//! LLM guardrail plugin.
//!
//! For queries the upstream `ai-classifier` flagged as `ai_traffic`,
//! enforces protective rules:
//!
//! - Reject `DROP` / `TRUNCATE`.
//! - Reject `DELETE` / `UPDATE` without a `WHERE` clause.
//! - Reject `SELECT` against tables marked `large` without a `LIMIT`.
//! - Require `tenant_id` filter on tables in `tenant_scoped_tables`.
//!
//! Reads the classifier's per-request KV (`req:<request_id>:ai_traffic`)
//! to decide whether to apply the rules. Untagged traffic passes
//! through unconditionally.

#![cfg_attr(not(test), no_std)]
extern crate alloc;

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use helios_plugin_abi::{
    abi_exports, read_args, write_result, PreQueryResult, QueryContext,
};

abi_exports!();

const TENANT_SCOPED_TABLES: &[&str] = &["users", "orders", "events", "messages"];
const LARGE_TABLES: &[&str] = &["events", "messages"];

#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    Allow,
    Block(&'static str),
}

pub fn evaluate(sql: &str) -> Verdict {
    let lower = sql.to_lowercase();
    let stripped = lower.trim();

    if stripped.starts_with("drop ") || stripped.starts_with("truncate ") {
        return Verdict::Block("DROP/TRUNCATE forbidden in LLM-tagged traffic");
    }

    let is_delete = stripped.starts_with("delete ");
    let is_update = stripped.starts_with("update ");
    if (is_delete || is_update) && !lower.contains(" where ") {
        return Verdict::Block("DELETE/UPDATE without WHERE forbidden in LLM-tagged traffic");
    }

    if stripped.starts_with("select ") {
        if let Some(table) = first_from_table(&lower) {
            if LARGE_TABLES.contains(&table.as_str()) && !lower.contains(" limit ") {
                return Verdict::Block("SELECT without LIMIT against large table");
            }
            if TENANT_SCOPED_TABLES.contains(&table.as_str())
                && !lower.contains("tenant_id")
            {
                return Verdict::Block("missing tenant_id filter on tenant-scoped table");
            }
        }
    }

    Verdict::Allow
}

fn first_from_table(lower: &str) -> Option<String> {
    let idx = lower.find(" from ")?;
    let rest = &lower[idx + 6..];
    let end = rest
        .find(|c: char| c == ' ' || c == ',' || c == '\n' || c == ';' || c == '(')
        .unwrap_or(rest.len());
    let mut t = rest[..end].trim().to_string();
    if let Some(dot) = t.rfind('.') {
        t = t[dot + 1..].to_string();
    }
    if t.is_empty() {
        None
    } else {
        Some(t)
    }
}

/// Returns `true` if the request looks like AI-generated traffic.
///
/// Self-contained heuristic: checks `application_name` for known LLM
/// keywords plus the explicit `helios.ai_traffic` opt-in. This
/// duplicates a slice of the ai-classifier logic on purpose —
/// per-plugin KV namespacing means the guardrail can't read the
/// classifier's results directly today, and we want the guardrail
/// useful even when the classifier isn't deployed.
///
/// Once the proxy ships a shared-attribute round-trip channel, the
/// guardrail can defer the decision entirely to the classifier.
fn is_ai_traffic(ctx: &QueryContext) -> bool {
    if let Some(app) = ctx.hook_context.attributes.get("application_name") {
        let lower = app.to_lowercase();
        for kw in [
            "gpt", "claude", "gemini", "llm", "chatbot", "agent", "openai", "anthropic",
        ] {
            if lower.contains(kw) {
                return true;
            }
        }
    }
    ctx.hook_context
        .attributes
        .get("helios.ai_traffic")
        .map(|s| s == "true")
        .unwrap_or(false)
}

#[no_mangle]
pub extern "C" fn pre_query(ptr: i32, len: i32) -> i64 {
    let bytes = unsafe { read_args(ptr, len) };
    let ctx: QueryContext = match serde_json::from_slice(bytes) {
        Ok(c) => c,
        Err(_) => return 0,
    };

    if !is_ai_traffic(&ctx) {
        let out = serde_json::to_vec(&PreQueryResult::Continue).unwrap_or_default();
        return write_result(&out);
    }

    let decision = match evaluate(&ctx.query) {
        Verdict::Allow => PreQueryResult::Continue,
        Verdict::Block(reason) => PreQueryResult::Block {
            reason: format!("llm-guardrail: {}", reason),
        },
    };
    let bytes = serde_json::to_vec(&decision).unwrap_or_default();
    write_result(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ai_ctx(query: &str) -> QueryContext {
        let mut c = QueryContext::default();
        c.query = query.into();
        c.hook_context
            .attributes
            .insert("application_name".into(), "claude-bot".into());
        c
    }

    #[test]
    fn blocks_drop_when_ai_tagged() {
        match evaluate("DROP TABLE users") {
            Verdict::Block(reason) => assert!(reason.contains("DROP/TRUNCATE")),
            Verdict::Allow => panic!("expected Block"),
        }
    }

    #[test]
    fn blocks_unbounded_delete() {
        assert!(matches!(evaluate("DELETE FROM users"), Verdict::Block(_)));
    }

    #[test]
    fn allows_delete_with_where() {
        assert_eq!(
            evaluate("DELETE FROM users WHERE id = 1 AND tenant_id = 'acme'"),
            Verdict::Allow
        );
    }

    #[test]
    fn blocks_select_no_limit_on_large_table() {
        assert!(matches!(
            evaluate("SELECT * FROM events WHERE tenant_id = 'a'"),
            Verdict::Block(_)
        ));
    }

    #[test]
    fn allows_select_with_limit() {
        assert_eq!(
            evaluate("SELECT * FROM events WHERE tenant_id = 'a' LIMIT 100"),
            Verdict::Allow
        );
    }

    #[test]
    fn blocks_missing_tenant_filter() {
        assert!(matches!(
            evaluate("SELECT id FROM users LIMIT 10"),
            Verdict::Block(_)
        ));
    }

    #[test]
    fn extracts_table_with_schema_qualifier() {
        assert_eq!(
            first_from_table("select * from public.users where 1=1").as_deref(),
            Some("users")
        );
    }

    #[test]
    fn untagged_human_traffic_passes_drop() {
        // Without an AI tag, the plugin doesn't enforce — operators
        // can run DROP via psql.
        let mut c = QueryContext::default();
        c.query = "DROP TABLE temp_t".into();
        c.hook_context
            .attributes
            .insert("application_name".into(), "psql".into());
        assert!(!is_ai_traffic(&c));
    }

    #[test]
    fn ai_tagged_drop_is_caught_via_full_path() {
        // Sanity: combine is_ai_traffic + evaluate.
        let ctx = ai_ctx("DROP TABLE users");
        assert!(is_ai_traffic(&ctx));
        assert!(matches!(evaluate(&ctx.query), Verdict::Block(_)));
    }
}
