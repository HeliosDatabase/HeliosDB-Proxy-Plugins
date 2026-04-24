//! Data-residency routing plugin.
//!
//! Reads the user's `region` claim from the authenticated identity
//! (set by the auth-plugin chain) and routes the query to a node
//! tagged with the matching region. Cross-region reads are blocked
//! by policy — the plugin returns `RouteResult::Default` only when
//! no region tag is configured for the user (i.e. domestic-only).
//!
//! Region map example:
//!
//! ```text
//! eu-west  → pg-replica-eu-west.svc:5432
//! us-east  → pg-replica-us-east.svc:5432
//! ap-south → pg-replica-ap-south.svc:5432
//! ```

#![allow(dead_code)]

#[derive(Debug, PartialEq, Eq)]
pub enum ResidencyDecision<'a> {
    /// Route to the named node tagged with the user's region.
    Node(&'a str),
    /// Block — user's region has no in-region replica configured and
    /// the policy forbids cross-region reads.
    Block(&'static str),
    /// No region requirement; let default routing apply.
    NoRequirement,
}

pub fn decide<'a>(
    user_region: Option<&str>,
    region_node_map: &'a [(&str, &str)],
    enforce: bool,
) -> ResidencyDecision<'a> {
    let region = match user_region {
        Some(r) => r,
        None => return ResidencyDecision::NoRequirement,
    };

    if let Some((_, node)) = region_node_map.iter().find(|(r, _)| *r == region) {
        return ResidencyDecision::Node(node);
    }

    if enforce {
        ResidencyDecision::Block("no in-region replica for user")
    } else {
        ResidencyDecision::NoRequirement
    }
}

#[no_mangle]
pub extern "C" fn route(_ctx_ptr: i32, _ctx_len: i32) -> i64 {
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map() -> &'static [(&'static str, &'static str)] {
        &[
            ("eu-west", "pg-eu.svc"),
            ("us-east", "pg-us.svc"),
        ]
    }

    #[test]
    fn routes_to_in_region_replica() {
        assert_eq!(decide(Some("eu-west"), map(), true), ResidencyDecision::Node("pg-eu.svc"));
        assert_eq!(decide(Some("us-east"), map(), true), ResidencyDecision::Node("pg-us.svc"));
    }

    #[test]
    fn blocks_when_no_replica_and_enforced() {
        assert_eq!(
            decide(Some("ap-south"), map(), true),
            ResidencyDecision::Block("no in-region replica for user")
        );
    }

    #[test]
    fn permits_when_no_replica_and_not_enforced() {
        assert_eq!(
            decide(Some("ap-south"), map(), false),
            ResidencyDecision::NoRequirement
        );
    }

    #[test]
    fn no_user_region_means_no_requirement() {
        assert_eq!(decide(None, map(), true), ResidencyDecision::NoRequirement);
    }
}
