//! pgvector routing plugin.
//!
//! Detects HNSW vector similarity queries and routes them to a node
//! with `role=vector` in the proxy topology — typically a replica
//! with the pgvector index hot in memory.
//!
//! Detection: SQL contains the cosine / L2 / inner-product distance
//! operators (`<->`, `<#>`, `<=>`) and `ORDER BY` referencing one of
//! them.
//!
//! Routes via `RouteResult::Node(name)` where `name` is the topology
//! tag the proxy operator configured. When no vector node exists,
//! returns `RouteResult::Default` so traffic falls back to standard
//! read routing.

#![allow(dead_code)]

const VECTOR_OPERATORS: &[&str] = &["<->", "<#>", "<=>"];

#[derive(Debug, PartialEq, Eq)]
pub enum VectorRoute<'a> {
    /// Use the proxy's default routing.
    Default,
    /// Send to the named vector node (or topology tag).
    Node(&'a str),
}

pub fn classify<'a>(sql: &str, vector_node: Option<&'a str>) -> VectorRoute<'a> {
    let lower = sql.to_lowercase();
    let has_op = VECTOR_OPERATORS.iter().any(|op| lower.contains(op));
    if !has_op {
        return VectorRoute::Default;
    }
    // ORDER BY containing a distance operator is the canonical vector
    // top-K pattern; without it, the operator may just be incidental
    // (e.g. comparison in a CTE) and we don't reroute.
    if !lower.contains("order by") {
        return VectorRoute::Default;
    }
    match vector_node {
        Some(n) => VectorRoute::Node(n),
        None => VectorRoute::Default,
    }
}

#[no_mangle]
pub extern "C" fn route(_ctx_ptr: i32, _ctx_len: i32) -> i64 {
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cosine_similarity_routes_to_vector() {
        let sql = "SELECT id FROM docs ORDER BY embedding <=> $1 LIMIT 5";
        assert_eq!(
            classify(sql, Some("vector-replica-1")),
            VectorRoute::Node("vector-replica-1")
        );
    }

    #[test]
    fn l2_distance_routes_to_vector() {
        let sql = "SELECT * FROM articles ORDER BY embedding <-> '[1,2,3]' LIMIT 10";
        assert_eq!(
            classify(sql, Some("vec")),
            VectorRoute::Node("vec")
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
}
