//! Column-level masking plugin.
//!
//! Rewrites `SELECT <col>, ...` into `SELECT mask_<col>(<col>), ...`
//! when the requesting identity's roles don't include the column's
//! `unmask_role`. Masking functions are SQL-side helpers the operator
//! installs in the database (e.g. `mask_ssn`, `mask_email`).
//!
//! Configuration shape (in plugin.toml once config glue lands):
//!
//! ```toml
//! [[rules]]
//! table = "users"
//! column = "ssn"
//! mask_function = "mask_ssn"
//! unmask_role = "pii_reader"
//!
//! [[rules]]
//! table = "users"
//! column = "email"
//! mask_function = "mask_email"
//! unmask_role = "pii_reader"
//! ```
//!
//! Plugin reads `identity.roles` from the unified RequestView and
//! decides per-column whether to wrap the column reference in the
//! mask function.

#![allow(dead_code)]

#[derive(Debug, Clone)]
pub struct MaskRule<'a> {
    pub table: &'a str,
    pub column: &'a str,
    pub mask_function: &'a str,
    pub unmask_role: &'a str,
}

/// Determine whether a given column reference should be masked given
/// the user's roles. Returns the mask function name when the column
/// should be wrapped; `None` to leave it alone.
pub fn mask_for(
    rules: &[MaskRule],
    table: &str,
    column: &str,
    user_roles: &[&str],
) -> Option<&'static str> {
    for rule in rules {
        if rule.table.eq_ignore_ascii_case(table)
            && rule.column.eq_ignore_ascii_case(column)
            && !user_roles.contains(&rule.unmask_role)
        {
            // SAFETY: rule.mask_function is &'a str borrowed from rules;
            // we transmute to 'static for ABI cleanliness in the stub
            // — real plugin returns owned String.
            return Some(unsafe {
                std::mem::transmute::<&str, &'static str>(rule.mask_function)
            });
        }
    }
    None
}

#[no_mangle]
pub extern "C" fn pre_query(_ctx_ptr: i32, _ctx_len: i32) -> i64 {
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules() -> Vec<MaskRule<'static>> {
        vec![
            MaskRule {
                table: "users",
                column: "ssn",
                mask_function: "mask_ssn",
                unmask_role: "pii_reader",
            },
            MaskRule {
                table: "users",
                column: "email",
                mask_function: "mask_email",
                unmask_role: "pii_reader",
            },
        ]
    }

    #[test]
    fn masks_when_role_missing() {
        let rules = rules();
        assert_eq!(
            mask_for(&rules, "users", "ssn", &["app_user"]),
            Some("mask_ssn")
        );
    }

    #[test]
    fn leaves_unmasked_when_role_present() {
        let rules = rules();
        assert_eq!(
            mask_for(&rules, "users", "ssn", &["pii_reader", "audit"]),
            None
        );
    }

    #[test]
    fn case_insensitive_match() {
        let rules = rules();
        assert_eq!(
            mask_for(&rules, "Users", "SSN", &[]),
            Some("mask_ssn")
        );
    }

    #[test]
    fn unrelated_columns_unaffected() {
        let rules = rules();
        assert_eq!(mask_for(&rules, "users", "id", &[]), None);
        assert_eq!(mask_for(&rules, "orders", "ssn", &[]), None);
    }
}
