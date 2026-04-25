//! Data-residency routing plugin.
//!
//! Reads the user's `region` claim from the authenticated identity
//! (set by the auth-plugin chain via `helios.region` in
//! `hook_context.attributes`) and routes the query to a node tagged
//! with the matching region.
//!
//! KV layout (per-plugin namespace `helios-plugin-residency-router`):
//!
//! - `region_map` — JSON of `Vec<(String, String)>` (region → node).
//!   The operator's `RoutingRule` reconciler seeds this.
//! - `enforce`    — JSON of `bool`. When true, missing-replica
//!   regions are blocked; when false, they fall back to default
//!   routing (useful in pre-prod where not every region has a
//!   replica yet).

#![cfg_attr(not(test), no_std)]
extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

use helios_plugin_abi::{
    abi_exports, kv_read, read_args, write_result, QueryContext, RouteResult,
};

abi_exports!();

#[derive(Debug, PartialEq, Eq)]
pub enum ResidencyDecision {
    /// Route to the named node tagged with the user's region.
    Node(String),
    /// Block — user's region has no in-region replica configured and
    /// the policy forbids cross-region reads.
    Block(&'static str),
    /// No region requirement; let default routing apply.
    NoRequirement,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResidencyConfig {
    /// (region, node_name) pairs.
    pub region_map: Vec<(String, String)>,
    /// When true, block users in regions with no replica. When false,
    /// fall through to default routing.
    pub enforce: bool,
}

pub fn decide(
    user_region: Option<&str>,
    cfg: &ResidencyConfig,
) -> ResidencyDecision {
    let region = match user_region {
        Some(r) if !r.is_empty() => r,
        _ => return ResidencyDecision::NoRequirement,
    };

    if let Some((_, node)) = cfg.region_map.iter().find(|(r, _)| r == region) {
        return ResidencyDecision::Node(node.clone());
    }

    if cfg.enforce {
        ResidencyDecision::Block("no in-region replica for user")
    } else {
        ResidencyDecision::NoRequirement
    }
}

fn load_config() -> ResidencyConfig {
    let map: Vec<(String, String)> = kv_read(b"region_map")
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default();
    let enforce: bool = kv_read(b"enforce")
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or(false);
    ResidencyConfig { region_map: map, enforce }
}

fn user_region_from(ctx: &QueryContext) -> Option<String> {
    ctx.hook_context
        .attributes
        .get("helios.region")
        .map(|s| s.to_string())
}

#[no_mangle]
pub extern "C" fn route(ptr: i32, len: i32) -> i64 {
    let bytes = unsafe { read_args(ptr, len) };
    let ctx: QueryContext = match serde_json::from_slice(bytes) {
        Ok(c) => c,
        Err(_) => return 0,
    };

    let cfg = load_config();
    let region = user_region_from(&ctx);
    let decision = decide(region.as_deref(), &cfg);

    let result = match decision {
        ResidencyDecision::Node(name) => RouteResult::Node { target: name },
        // RouteResult has no native Block — encode as a non-existent
        // target the proxy will fail to resolve. The host's route
        // dispatch surfaces this as an error to the client. A future
        // RouteResult::Block variant in the ABI would be cleaner.
        ResidencyDecision::Block(_) => RouteResult::Node {
            target: "__residency_block__".to_string(),
        },
        ResidencyDecision::NoRequirement => RouteResult::Default,
    };
    let bytes = serde_json::to_vec(&result).unwrap_or_default();
    write_result(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(enforce: bool) -> ResidencyConfig {
        ResidencyConfig {
            region_map: alloc::vec![
                ("eu-west".into(), "pg-eu.svc".into()),
                ("us-east".into(), "pg-us.svc".into()),
            ],
            enforce,
        }
    }

    #[test]
    fn routes_to_in_region_replica() {
        assert_eq!(
            decide(Some("eu-west"), &cfg(true)),
            ResidencyDecision::Node("pg-eu.svc".into())
        );
        assert_eq!(
            decide(Some("us-east"), &cfg(true)),
            ResidencyDecision::Node("pg-us.svc".into())
        );
    }

    #[test]
    fn blocks_when_no_replica_and_enforced() {
        assert_eq!(
            decide(Some("ap-south"), &cfg(true)),
            ResidencyDecision::Block("no in-region replica for user")
        );
    }

    #[test]
    fn permits_when_no_replica_and_not_enforced() {
        assert_eq!(
            decide(Some("ap-south"), &cfg(false)),
            ResidencyDecision::NoRequirement
        );
    }

    #[test]
    fn no_user_region_means_no_requirement() {
        assert_eq!(decide(None, &cfg(true)), ResidencyDecision::NoRequirement);
        assert_eq!(decide(Some(""), &cfg(true)), ResidencyDecision::NoRequirement);
    }

    #[test]
    fn user_region_from_reads_attribute() {
        let mut ctx = QueryContext::default();
        ctx.hook_context
            .attributes
            .insert("helios.region".into(), "eu-west".into());
        assert_eq!(user_region_from(&ctx).as_deref(), Some("eu-west"));
    }
}
