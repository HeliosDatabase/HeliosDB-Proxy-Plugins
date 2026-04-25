//! pgvector routing plugin.
//!
//! Detects pgvector similarity queries (HNSW / IVF top-K via `<->`,
//! `<#>`, `<=>` operators in `ORDER BY`) and routes them to a node
//! tagged in the proxy topology — typically a replica with the
//! pgvector index hot in memory.
//!
//! The routed node name is configured per-deployment via the
//! `helios.vector_node` attribute (set by the operator from the
//! `RoutingRule` CRD). Falls back to `RouteResult::Default` when the
//! attribute is missing.

#![cfg_attr(not(test), no_std)]
extern crate alloc;

use alloc::string::{String, ToString};

use helios_plugin_abi::{
    abi_exports, read_args, write_result, QueryContext, RouteResult,
};

abi_exports!();

const VECTOR_OPERATORS: &[&str] = &["<->", "<#>", "<=>"];

#[derive(Debug, PartialEq, Eq)]
pub enum VectorRoute {
    /// Use the proxy's default routing.
    Default,
    /// Send to the named vector node (or topology tag).
    Node(String),
}

/// Pure-function classifier — no IO. The vector_node argument comes
/// from the request's `hook_context.attributes["helios.vector_node"]`.
pub fn classify(sql: &str, vector_node: Option<&str>) -> VectorRoute {
    let lower = sql.to_lowercase();
    let has_op = VECTOR_OPERATORS.iter().any(|op| lower.contains(op));
    if !has_op {
        return VectorRoute::Default;
    }
    // ORDER BY containing a distance operator is the canonical vector
    // top-K pattern; without it, the operator may be incidental
    // (e.g. comparison in a CTE) and we shouldn't reroute.
    if !lower.contains("order by") {
        return VectorRoute::Default;
    }
    match vector_node {
        Some(n) if !n.is_empty() => VectorRoute::Node(n.to_string()),
        _ => VectorRoute::Default,
    }
}

#[no_mangle]
pub extern "C" fn route(ptr: i32, len: i32) -> i64 {
    let bytes = unsafe { read_args(ptr, len) };
    let ctx: QueryContext = match serde_json::from_slice(bytes) {
        Ok(c) => c,
        Err(_) => return 0,
    };
    let target = ctx.hook_context.attributes.get("helios.vector_node");
    let decision = classify(&ctx.query, target.map(|s| s.as_str()));

    let result = match decision {
        VectorRoute::Default => RouteResult::Default,
        VectorRoute::Node(name) => RouteResult::Node { target: name },
    };
    let bytes = serde_json::to_vec(&result).unwrap_or_default();
    write_result(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cosine_similarity_routes_to_vector() {
        let sql = "SELECT id FROM docs ORDER BY embedding <=> $1 LIMIT 5";
        assert_eq!(
            classify(sql, Some("vector-replica-1")),
            VectorRoute::Node("vector-replica-1".into())
        );
    }

    #[test]
    fn l2_distance_routes_to_vector() {
        let sql = "SELECT * FROM articles ORDER BY embedding <-> '[1,2,3]' LIMIT 10";
        assert_eq!(
            classify(sql, Some("vec")),
            VectorRoute::Node("vec".into())
        );
    }

    #[test]
    fn no_order_by_returns_default() {
        let sql = "SELECT id FROM t WHERE embedding <=> $1 < 0.5";
        assert_eq!(classify(sql, Some("vec")), VectorRoute::Default);
    }

    #[test]
    fn no_operator_returns_default() {
        assert_eq!(classify("SELECT * FROM t", Some("vec")), VectorRoute::Default);
    }

    #[test]
    fn no_vector_node_falls_back_to_default() {
        let sql = "SELECT id FROM docs ORDER BY embedding <=> $1 LIMIT 5";
        assert_eq!(classify(sql, None), VectorRoute::Default);
    }

    #[test]
    fn empty_vector_node_falls_back_to_default() {
        let sql = "SELECT id FROM docs ORDER BY embedding <=> $1 LIMIT 5";
        assert_eq!(classify(sql, Some("")), VectorRoute::Default);
    }
}
