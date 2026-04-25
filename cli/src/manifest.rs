//! Plugin OCI artefact manifest.
//!
//! An artefact is a `.tar.gz` containing exactly three entries:
//!
//! ```text
//! manifest.json   ← Manifest serialised here
//! plugin.wasm     ← the WASM binary
//! plugin.sig      ← optional Ed25519 signature, base64-encoded
//! ```
//!
//! The manifest is small and stable: every field is required except
//! `signature_algorithm` (defaults to `"ed25519"` when present).
//!
//! Wire format is versioned via `schema_version`. Bumping major
//! versions is a hard break; minor adds new optional fields.

use serde::{Deserialize, Serialize};

/// Current artefact schema version. Major.minor; breaking changes
/// bump the major.
pub const SCHEMA_VERSION: &str = "1.0";

/// Plugin OCI artefact manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    /// Schema version (e.g. "1.0"). Tools refuse incompatible
    /// majors.
    pub schema_version: String,

    /// Human-readable plugin name. Matches the wasm package name.
    pub name: String,

    /// Plugin version (semver recommended but not enforced — the CLI
    /// only treats it as an opaque tag).
    pub version: String,

    /// One-line description for `helios-plugin inspect` output.
    pub description: String,

    /// SPDX license identifier.
    pub license: String,

    /// Hooks the plugin implements. Strings (not enums) so adding
    /// new proxy hooks doesn't require re-cutting every artefact.
    pub hooks: Vec<String>,

    /// Lower-case hex SHA-256 of `plugin.wasm`. The CLI computes
    /// this when packing; the loader can recompute and compare for
    /// integrity.
    pub wasm_sha256: String,

    /// Lower-case hex SHA-256 of the signature blob (when present).
    /// Lets a registry de-duplicate at the manifest level.
    #[serde(default)]
    pub signature_sha256: Option<String>,

    /// Signature algorithm. Today always "ed25519" when a signature
    /// is present.
    #[serde(default)]
    pub signature_algorithm: Option<String>,

    /// RFC 3339 timestamp the artefact was packed.
    pub packed_at: String,
}

impl Manifest {
    pub fn schema_version_compatible(&self) -> bool {
        self.schema_version
            .split('.')
            .next()
            .map(|major| major == SCHEMA_VERSION.split('.').next().unwrap())
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Manifest {
        Manifest {
            schema_version: SCHEMA_VERSION.to_string(),
            name: "helios-plugin-cost-governor".into(),
            version: "0.1.0".into(),
            description: "Per-tenant cost governance".into(),
            license: "AGPL-3.0-only".into(),
            hooks: vec!["pre_query".into(), "post_query".into()],
            wasm_sha256: "deadbeef".repeat(8),
            signature_sha256: None,
            signature_algorithm: None,
            packed_at: "2026-04-25T12:00:00Z".into(),
        }
    }

    #[test]
    fn serde_round_trip() {
        let m = sample();
        let json = serde_json::to_string(&m).unwrap();
        let back: Manifest = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, m.name);
        assert_eq!(back.wasm_sha256, m.wasm_sha256);
    }

    #[test]
    fn schema_version_compat_accepts_same_major() {
        let mut m = sample();
        m.schema_version = "1.5".into();
        assert!(m.schema_version_compatible());
    }

    #[test]
    fn schema_version_compat_rejects_different_major() {
        let mut m = sample();
        m.schema_version = "2.0".into();
        assert!(!m.schema_version_compatible());
    }

    #[test]
    fn signature_fields_optional() {
        let m = sample();
        assert!(m.signature_sha256.is_none());
        let json = serde_json::to_string(&m).unwrap();
        // Signature fields serialise as null but are accepted as
        // missing on the way back in (serde default).
        assert!(json.contains("\"signature_sha256\":null"));
    }
}
