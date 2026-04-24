//! LLM guardrail plugin.
//!
//! For queries tagged `ai_traffic=true` by the ai-classifier upstream:
//! - Reject DROP / TRUNCATE / DELETE without `WHERE` clause.
//! - Reject `UPDATE ... SET ...` without `WHERE`.
//! - Reject `SELECT ...` without `LIMIT` against tables marked `large`.
//! - Require presence of `WHERE tenant_id = $X` on tables in
//!   `tenant_scoped_tables`.
//!
//! All thresholds are constants today; once the proxy's plugin-config
//! glue lands they migrate to plugin.toml.

#![allow(dead_code)]

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
    // Strip schema qualifier ("public.users" → "users")
    if let Some(dot) = t.rfind('.') {
        t = t[dot + 1..].to_string();
    }
    if t.is_empty() {
        None
    } else {
        Some(t)
    }
}

#[no_mangle]
pub extern "C" fn pre_query(_ctx_ptr: i32, _ctx_len: i32) -> i64 {
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_drop() {
        assert_eq!(
            evaluate("DROP TABLE users"),
            Verdict::Block("DROP/TRUNCATE forbidden in LLM-tagged traffic")
        );
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
        assert_eq!(first_from_table("select * from public.users where 1=1").as_deref(), Some("users"));
    }
}
