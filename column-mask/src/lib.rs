//! Column-level masking plugin.
//!
//! Rewrites `SELECT <col>, ...` into `SELECT <mask_fn>(<col>) AS <col>, ...`
//! when the requesting identity's roles don't include the column's
//! `unmask_role`. Mask functions are SQL-side helpers the operator
//! installs in the database (e.g. `mask_ssn`, `mask_email`).
//!
//! Rule storage (per-plugin KV namespace `helios-plugin-column-mask`):
//!
//! - Single key `rules` → JSON-encoded `Vec<MaskRule>`. The operator
//!   reconciler writes this whenever an `AuditPolicy` CR changes;
//!   plugins read it on each pre_query call.
//!
//! Rewriting strategy (intentionally simple — full SQL parsing is too
//! big for a WASM plugin in v1):
//!
//! 1. For each rule whose `table` appears anywhere in the lower-cased
//!    SQL (substring match), and where the user's roles do NOT include
//!    `unmask_role`,
//! 2. Replace bare references to `<column>` with
//!    `<mask_function>(<column>) AS <column>` once.
//!
//! Returns `PreQueryResult::Rewrite { sql }` when at least one rule
//! matched, `PreQueryResult::Continue` otherwise.

#![cfg_attr(not(test), no_std)]
extern crate alloc;

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

use helios_plugin_abi::{
    abi_exports, kv_read, read_args, write_result, PreQueryResult, QueryContext,
};

abi_exports!();

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaskRule {
    pub table: String,
    pub column: String,
    pub mask_function: String,
    pub unmask_role: String,
}

/// Pure decision: should this column be wrapped in a mask call?
/// Returns the mask function name; `None` to leave the column alone.
pub fn mask_for<'a>(
    rules: &'a [MaskRule],
    table: &str,
    column: &str,
    user_roles: &[&str],
) -> Option<&'a str> {
    for rule in rules {
        if rule.table.eq_ignore_ascii_case(table)
            && rule.column.eq_ignore_ascii_case(column)
            && !user_roles
                .iter()
                .any(|r| r.eq_ignore_ascii_case(&rule.unmask_role))
        {
            return Some(&rule.mask_function);
        }
    }
    None
}

/// Rewrite an SQL string by applying every applicable rule once.
/// Substring-based — fragile but adequate for the common
/// `SELECT col1, col2, ...` shape this plugin targets. Returns
/// (rewritten_sql, did_rewrite).
pub fn apply_rules(sql: &str, rules: &[MaskRule], user_roles: &[&str]) -> (String, bool) {
    let lower = sql.to_lowercase();
    let mut out = sql.to_string();
    let mut changed = false;

    for rule in rules {
        if !lower.contains(&rule.table.to_lowercase()) {
            continue;
        }
        if user_roles
            .iter()
            .any(|r| r.eq_ignore_ascii_case(&rule.unmask_role))
        {
            continue;
        }
        // Skip if already wrapped — avoid double-wrap on reconciles.
        let already = format!("{}(", rule.mask_function);
        if out.contains(&already) {
            continue;
        }
        // Look for the bare column name in the original case-preserving
        // text. Only replaces whole-word bare references.
        let target = rule.column.as_str();
        if let Some(idx) = find_word(&out, target) {
            let replacement = format!(
                "{}({}) AS {}",
                rule.mask_function, target, target
            );
            out = format!("{}{}{}", &out[..idx], replacement, &out[idx + target.len()..]);
            changed = true;
        }
    }
    (out, changed)
}

/// Find the first whole-word occurrence of `needle` in `haystack`.
/// "Whole-word" = surrounded by non-alphanumeric / non-underscore.
fn find_word(haystack: &str, needle: &str) -> Option<usize> {
    let bytes = haystack.as_bytes();
    let n = needle.len();
    if n == 0 {
        return None;
    }
    let mut i = 0;
    while i + n <= bytes.len() {
        if haystack[i..i + n].eq_ignore_ascii_case(needle) {
            let pre_ok = i == 0 || !is_word_byte(bytes[i - 1]);
            let post_ok = i + n == bytes.len() || !is_word_byte(bytes[i + n]);
            if pre_ok && post_ok {
                return Some(i);
            }
        }
        i += 1;
    }
    None
}

fn is_word_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

fn parse_roles(ctx: &QueryContext) -> Vec<String> {
    ctx.hook_context
        .attributes
        .get("identity.roles")
        .map(|s| s.split(',').map(|r| r.trim().to_string()).collect())
        .unwrap_or_default()
}

#[no_mangle]
pub extern "C" fn pre_query(ptr: i32, len: i32) -> i64 {
    let bytes = unsafe { read_args(ptr, len) };
    let ctx: QueryContext = match serde_json::from_slice(bytes) {
        Ok(c) => c,
        Err(_) => return 0,
    };

    let rules: Vec<MaskRule> = kv_read(b"rules")
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default();

    if rules.is_empty() {
        let out = serde_json::to_vec(&PreQueryResult::Continue).unwrap_or_default();
        return write_result(&out);
    }

    let role_strings = parse_roles(&ctx);
    let role_refs: Vec<&str> = role_strings.iter().map(|s| s.as_str()).collect();
    let (rewritten, changed) = apply_rules(&ctx.query, &rules, &role_refs);

    let result = if changed {
        PreQueryResult::Rewrite { sql: rewritten }
    } else {
        PreQueryResult::Continue
    };
    let bytes = serde_json::to_vec(&result).unwrap_or_default();
    write_result(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules() -> Vec<MaskRule> {
        vec![
            MaskRule {
                table: "users".into(),
                column: "ssn".into(),
                mask_function: "mask_ssn".into(),
                unmask_role: "pii_reader".into(),
            },
            MaskRule {
                table: "users".into(),
                column: "email".into(),
                mask_function: "mask_email".into(),
                unmask_role: "pii_reader".into(),
            },
        ]
    }

    #[test]
    fn masks_when_role_missing() {
        assert_eq!(
            mask_for(&rules(), "users", "ssn", &["app_user"]),
            Some("mask_ssn")
        );
    }

    #[test]
    fn leaves_unmasked_when_role_present() {
        assert_eq!(
            mask_for(&rules(), "users", "ssn", &["pii_reader", "audit"]),
            None
        );
    }

    #[test]
    fn case_insensitive_table_column_role_match() {
        assert_eq!(mask_for(&rules(), "Users", "SSN", &[]), Some("mask_ssn"));
        assert_eq!(
            mask_for(&rules(), "users", "ssn", &["PII_READER"]),
            None
        );
    }

    #[test]
    fn unrelated_columns_unaffected() {
        assert_eq!(mask_for(&rules(), "users", "id", &[]), None);
        assert_eq!(mask_for(&rules(), "orders", "ssn", &[]), None);
    }

    #[test]
    fn apply_rules_rewrites_select() {
        let sql = "SELECT id, ssn, email FROM users WHERE id = 1";
        let (out, changed) = apply_rules(sql, &rules(), &[]);
        assert!(changed);
        assert!(out.contains("mask_ssn(ssn) AS ssn"));
        assert!(out.contains("mask_email(email) AS email"));
    }

    #[test]
    fn apply_rules_skips_when_user_has_role() {
        let sql = "SELECT id, ssn FROM users";
        let (out, changed) = apply_rules(sql, &rules(), &["pii_reader"]);
        assert!(!changed);
        assert_eq!(out, sql);
    }

    #[test]
    fn find_word_skips_substring_matches() {
        // "ssn" should not match "ssna" or "_ssn"
        assert!(find_word("SELECT ssna FROM users", "ssn").is_none());
        assert!(find_word("SELECT _ssn FROM users", "ssn").is_none());
        assert_eq!(find_word("SELECT ssn FROM users", "ssn"), Some(7));
    }

    #[test]
    fn apply_rules_idempotent_on_second_pass() {
        let sql = "SELECT ssn FROM users";
        let rules = rules();
        let (after_first, _) = apply_rules(sql, &rules, &[]);
        let (after_second, changed_second) = apply_rules(&after_first, &rules, &[]);
        assert!(!changed_second, "second pass should not re-wrap");
        assert_eq!(after_first, after_second);
    }
}
