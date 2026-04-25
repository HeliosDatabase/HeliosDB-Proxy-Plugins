//! Artefact format: tar.gz containing
//!   manifest.json
//!   plugin.wasm
//!   plugin.sig   (optional)
//!
//! All three live at the tarball root with no nesting. Order on disk
//! is fixed (manifest first) so streaming readers can short-circuit
//! the schema check before reading the wasm body.

use anyhow::{anyhow, bail, Context, Result};
use base64::Engine as _;
use ed25519_dalek::Verifier;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{Cursor, Read, Write};
use std::path::Path;

use crate::manifest::{Manifest, SCHEMA_VERSION};

pub const ENTRY_MANIFEST: &str = "manifest.json";
pub const ENTRY_WASM: &str = "plugin.wasm";
pub const ENTRY_SIG: &str = "plugin.sig";

/// What `pack` writes to disk.
pub struct PackInputs<'a> {
    pub name: &'a str,
    pub version: &'a str,
    pub description: &'a str,
    pub license: &'a str,
    pub hooks: Vec<String>,
    pub wasm_path: &'a Path,
    pub signature_path: Option<&'a Path>,
}

/// Pack a plugin into a `.tar.gz` artefact at `out_path`. Computes
/// SHA-256 over the wasm bytes; copies the optional signature blob
/// in verbatim. Returns the manifest written.
pub fn pack(inputs: &PackInputs, out_path: &Path) -> Result<Manifest> {
    let wasm_bytes = fs::read(inputs.wasm_path)
        .with_context(|| format!("read wasm {}", inputs.wasm_path.display()))?;
    if wasm_bytes.len() < 8 || &wasm_bytes[0..4] != b"\x00asm" {
        bail!("{} is not a valid WASM binary (magic mismatch)", inputs.wasm_path.display());
    }
    let wasm_sha256 = sha256_hex(&wasm_bytes);

    let (sig_bytes, signature_sha256, signature_algorithm) =
        if let Some(p) = inputs.signature_path {
            let raw = fs::read(p)
                .with_context(|| format!("read signature {}", p.display()))?;
            let sig_hash = sha256_hex(&raw);
            (Some(raw), Some(sig_hash), Some("ed25519".to_string()))
        } else {
            (None, None, None)
        };

    let manifest = Manifest {
        schema_version: SCHEMA_VERSION.to_string(),
        name: inputs.name.to_string(),
        version: inputs.version.to_string(),
        description: inputs.description.to_string(),
        license: inputs.license.to_string(),
        hooks: inputs.hooks.clone(),
        wasm_sha256,
        signature_sha256,
        signature_algorithm,
        packed_at: now_rfc3339(),
    };
    let manifest_json = serde_json::to_vec_pretty(&manifest)
        .context("serialise manifest")?;

    // Build the tarball. Entry order is fixed: manifest first so a
    // streaming reader can short-circuit on schema mismatch before
    // touching the wasm body.
    let out_file = File::create(out_path)
        .with_context(|| format!("create {}", out_path.display()))?;
    let gz = GzEncoder::new(out_file, Compression::default());
    let mut tar = tar::Builder::new(gz);

    write_tar_entry(&mut tar, ENTRY_MANIFEST, &manifest_json)?;
    write_tar_entry(&mut tar, ENTRY_WASM, &wasm_bytes)?;
    if let Some(ref bytes) = sig_bytes {
        write_tar_entry(&mut tar, ENTRY_SIG, bytes)?;
    }

    let gz = tar.into_inner().context("finalise tar")?;
    gz.finish().context("finalise gzip")?;

    Ok(manifest)
}

/// What `inspect` / `verify` reads back.
#[derive(Debug)]
pub struct UnpackedArtefact {
    pub manifest: Manifest,
    pub wasm: Vec<u8>,
    pub signature: Option<Vec<u8>>,
}

/// Read a `.tar.gz` artefact off disk.
pub fn unpack(path: &Path) -> Result<UnpackedArtefact> {
    let bytes = fs::read(path)
        .with_context(|| format!("read {}", path.display()))?;
    let gz = GzDecoder::new(Cursor::new(bytes));
    let mut archive = tar::Archive::new(gz);

    let mut manifest: Option<Manifest> = None;
    let mut wasm: Option<Vec<u8>> = None;
    let mut signature: Option<Vec<u8>> = None;

    for entry in archive.entries().context("read tar entries")? {
        let mut entry = entry.context("tar entry header")?;
        let entry_path = entry
            .path()
            .context("entry path")?
            .to_string_lossy()
            .to_string();
        let mut buf = Vec::new();
        entry.read_to_end(&mut buf).context("read entry body")?;
        match entry_path.as_str() {
            ENTRY_MANIFEST => {
                let m: Manifest =
                    serde_json::from_slice(&buf).context("parse manifest.json")?;
                if !m.schema_version_compatible() {
                    bail!(
                        "incompatible artefact schema version {} (this CLI supports {})",
                        m.schema_version,
                        SCHEMA_VERSION
                    );
                }
                manifest = Some(m);
            }
            ENTRY_WASM => wasm = Some(buf),
            ENTRY_SIG => signature = Some(buf),
            other => {
                // Unknown entries are forward-compat extension space;
                // ignore quietly so future formats don't break older
                // CLIs that just want to inspect.
                let _ = other;
            }
        }
    }

    let manifest = manifest.ok_or_else(|| anyhow!("artefact missing manifest.json"))?;
    let wasm = wasm.ok_or_else(|| anyhow!("artefact missing plugin.wasm"))?;

    // Integrity: recompute wasm SHA-256 and compare.
    let actual = sha256_hex(&wasm);
    if actual != manifest.wasm_sha256 {
        bail!(
            "wasm sha256 mismatch: manifest claims {}, actual {}",
            manifest.wasm_sha256,
            actual
        );
    }

    Ok(UnpackedArtefact { manifest, wasm, signature })
}

/// Verify a packed artefact's signature against a trust root
/// (directory of `*.pub` files, base64 raw Ed25519 keys — same
/// format the proxy's `SignatureVerifier` reads). Returns the
/// label of the matching key.
pub fn verify(art: &UnpackedArtefact, trust_root: &Path) -> Result<String> {
    let sig_b64 = art
        .signature
        .as_ref()
        .ok_or_else(|| anyhow!("artefact has no signature"))?;
    let sig_str = std::str::from_utf8(sig_b64)
        .context("signature must be UTF-8 base64")?
        .trim();
    let sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(sig_str)
        .context("base64 decode signature")?;
    if sig_bytes.len() != 64 {
        bail!("signature should be 64 bytes, got {}", sig_bytes.len());
    }
    let mut arr = [0u8; 64];
    arr.copy_from_slice(&sig_bytes);
    let sig = ed25519_dalek::Signature::from_bytes(&arr);

    for entry in fs::read_dir(trust_root)
        .with_context(|| format!("read trust root {}", trust_root.display()))?
    {
        let entry = entry?;
        let p = entry.path();
        if p.extension().and_then(|s| s.to_str()) != Some("pub") {
            continue;
        }
        let raw = fs::read_to_string(&p).context("read pubkey file")?;
        let raw = raw.trim();
        let bytes = match base64::engine::general_purpose::STANDARD.decode(raw) {
            Ok(b) => b,
            Err(_) => continue,
        };
        if bytes.len() != 32 {
            continue;
        }
        let mut karr = [0u8; 32];
        karr.copy_from_slice(&bytes);
        let key = match ed25519_dalek::VerifyingKey::from_bytes(&karr) {
            Ok(k) => k,
            Err(_) => continue,
        };
        if key.verify(&art.wasm, &sig).is_ok() {
            let label = p
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("(unknown)")
                .to_string();
            return Ok(label);
        }
    }
    bail!("signature did not match any trusted key in {}", trust_root.display())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut s = String::with_capacity(64);
    for b in digest.iter() {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

fn write_tar_entry<W: Write>(
    tar: &mut tar::Builder<W>,
    name: &str,
    bytes: &[u8],
) -> Result<()> {
    let mut header = tar::Header::new_gnu();
    header.set_path(name).context("set entry path")?;
    header.set_size(bytes.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    tar.append(&header, bytes).context("append entry")?;
    Ok(())
}

fn now_rfc3339() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // Bare seconds → ISO 8601 without dragging in chrono just for
    // this. Format is fine for an artefact timestamp.
    let secs = now as i64;
    let (year, month, day, hour, minute, second) = epoch_to_ymdhms(secs);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, hour, minute, second
    )
}

/// Convert Unix epoch seconds to (year, month, day, hour, minute,
/// second) UTC. Implementation handles 1970–9999. Tested against
/// canonical values below.
fn epoch_to_ymdhms(mut secs: i64) -> (i32, u32, u32, u32, u32, u32) {
    let second = (secs.rem_euclid(60)) as u32;
    secs = secs.div_euclid(60);
    let minute = (secs.rem_euclid(60)) as u32;
    secs = secs.div_euclid(60);
    let hour = (secs.rem_euclid(24)) as u32;
    let mut days = secs.div_euclid(24);

    let mut year: i32 = 1970;
    loop {
        let leap = is_leap(year);
        let days_in_year = if leap { 366 } else { 365 };
        if days >= days_in_year as i64 {
            days -= days_in_year as i64;
            year += 1;
        } else {
            break;
        }
    }
    let days_in_month = [31, if is_leap(year) { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let mut month = 1;
    let mut remaining = days as u32;
    for &dim in &days_in_month {
        if remaining >= dim {
            remaining -= dim;
            month += 1;
        } else {
            break;
        }
    }
    let day = remaining + 1;
    (year, month, day, hour, minute, second)
}

fn is_leap(y: i32) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn fake_wasm(extra: &[u8]) -> Vec<u8> {
        let mut v = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
        v.extend_from_slice(extra);
        v
    }

    fn write_pubkey(dir: &Path, label: &str, key: &SigningKey) {
        let pub_bytes = key.verifying_key().to_bytes();
        let b64 = base64::engine::general_purpose::STANDARD.encode(pub_bytes);
        std::fs::write(dir.join(format!("{label}.pub")), b64).unwrap();
    }

    #[test]
    fn pack_then_unpack_round_trips_manifest_and_wasm() {
        let tmp = tempfile::tempdir().unwrap();
        let wasm_path = tmp.path().join("plugin.wasm");
        std::fs::write(&wasm_path, fake_wasm(b"body")).unwrap();
        let out_path = tmp.path().join("art.tar.gz");

        let inputs = PackInputs {
            name: "test-plugin",
            version: "1.2.3",
            description: "test",
            license: "AGPL-3.0-only",
            hooks: vec!["pre_query".into()],
            wasm_path: &wasm_path,
            signature_path: None,
        };
        let manifest = pack(&inputs, &out_path).unwrap();
        assert_eq!(manifest.name, "test-plugin");
        assert_eq!(manifest.wasm_sha256.len(), 64);

        let unpacked = unpack(&out_path).unwrap();
        assert_eq!(unpacked.manifest.name, "test-plugin");
        assert_eq!(unpacked.wasm, fake_wasm(b"body"));
        assert!(unpacked.signature.is_none());
    }

    #[test]
    fn pack_includes_signature_when_present() {
        let tmp = tempfile::tempdir().unwrap();
        let wasm_path = tmp.path().join("plugin.wasm");
        let sig_path = tmp.path().join("plugin.sig");
        std::fs::write(&wasm_path, fake_wasm(b"x")).unwrap();
        std::fs::write(&sig_path, "AAAA").unwrap();

        let out_path = tmp.path().join("art.tar.gz");
        pack(
            &PackInputs {
                name: "p",
                version: "0.0.1",
                description: "",
                license: "AGPL-3.0-only",
                hooks: vec![],
                wasm_path: &wasm_path,
                signature_path: Some(&sig_path),
            },
            &out_path,
        )
        .unwrap();

        let unpacked = unpack(&out_path).unwrap();
        assert_eq!(unpacked.signature.as_deref(), Some(&b"AAAA"[..]));
        assert!(unpacked.manifest.signature_sha256.is_some());
        assert_eq!(unpacked.manifest.signature_algorithm.as_deref(), Some("ed25519"));
    }

    #[test]
    fn unpack_rejects_tampered_wasm() {
        let tmp = tempfile::tempdir().unwrap();
        let wasm_path = tmp.path().join("plugin.wasm");
        std::fs::write(&wasm_path, fake_wasm(b"original")).unwrap();
        let out_path = tmp.path().join("art.tar.gz");
        pack(
            &PackInputs {
                name: "p",
                version: "0.0.1",
                description: "",
                license: "AGPL-3.0-only",
                hooks: vec![],
                wasm_path: &wasm_path,
                signature_path: None,
            },
            &out_path,
        )
        .unwrap();

        // Hand-rebuild a tarball with the manifest from the original
        // plus tampered wasm bytes.
        let original = unpack(&out_path).unwrap();
        let tampered_path = tmp.path().join("tampered.tar.gz");
        let tampered_wasm = fake_wasm(b"TAMPERED");
        let manifest_json = serde_json::to_vec(&original.manifest).unwrap();
        let f = File::create(&tampered_path).unwrap();
        let gz = GzEncoder::new(f, Compression::default());
        let mut tar = tar::Builder::new(gz);
        write_tar_entry(&mut tar, ENTRY_MANIFEST, &manifest_json).unwrap();
        write_tar_entry(&mut tar, ENTRY_WASM, &tampered_wasm).unwrap();
        let gz = tar.into_inner().unwrap();
        gz.finish().unwrap();

        let err = unpack(&tampered_path).unwrap_err();
        assert!(
            err.to_string().contains("sha256 mismatch"),
            "expected sha256 mismatch, got: {}",
            err
        );
    }

    #[test]
    fn verify_accepts_correctly_signed_artefact() {
        let tmp = tempfile::tempdir().unwrap();
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let wasm = fake_wasm(b"hello-world");
        let wasm_path = tmp.path().join("plugin.wasm");
        std::fs::write(&wasm_path, &wasm).unwrap();

        // Sign the wasm bytes (matches the proxy's SignatureVerifier
        // contract — Ed25519 over the .wasm bytes).
        let sig = key.sign(&wasm);
        let sig_b64 = base64::engine::general_purpose::STANDARD.encode(sig.to_bytes());
        let sig_path = tmp.path().join("plugin.sig");
        std::fs::write(&sig_path, sig_b64).unwrap();

        let out_path = tmp.path().join("art.tar.gz");
        pack(
            &PackInputs {
                name: "p",
                version: "0.0.1",
                description: "",
                license: "AGPL-3.0-only",
                hooks: vec![],
                wasm_path: &wasm_path,
                signature_path: Some(&sig_path),
            },
            &out_path,
        )
        .unwrap();

        let trust_dir = tempfile::tempdir().unwrap();
        write_pubkey(trust_dir.path(), "official", &key);

        let unpacked = unpack(&out_path).unwrap();
        let label = verify(&unpacked, trust_dir.path()).unwrap();
        assert_eq!(label, "official");
    }

    #[test]
    fn verify_rejects_untrusted_signer() {
        let tmp = tempfile::tempdir().unwrap();
        let trusted = SigningKey::from_bytes(&[1u8; 32]);
        let attacker = SigningKey::from_bytes(&[2u8; 32]);
        let wasm = fake_wasm(b"xyz");
        let wasm_path = tmp.path().join("plugin.wasm");
        std::fs::write(&wasm_path, &wasm).unwrap();

        let sig = attacker.sign(&wasm);
        let sig_b64 = base64::engine::general_purpose::STANDARD.encode(sig.to_bytes());
        let sig_path = tmp.path().join("plugin.sig");
        std::fs::write(&sig_path, sig_b64).unwrap();

        let out_path = tmp.path().join("art.tar.gz");
        pack(
            &PackInputs {
                name: "p",
                version: "0.0.1",
                description: "",
                license: "AGPL-3.0-only",
                hooks: vec![],
                wasm_path: &wasm_path,
                signature_path: Some(&sig_path),
            },
            &out_path,
        )
        .unwrap();

        let trust_dir = tempfile::tempdir().unwrap();
        write_pubkey(trust_dir.path(), "official", &trusted);

        let unpacked = unpack(&out_path).unwrap();
        let err = verify(&unpacked, trust_dir.path()).unwrap_err();
        assert!(
            err.to_string().contains("did not match"),
            "expected mismatch error, got: {}",
            err
        );
    }

    #[test]
    fn epoch_to_ymdhms_matches_canonical_dates() {
        // 1970-01-01 00:00:00 UTC — Unix epoch.
        assert_eq!(epoch_to_ymdhms(0), (1970, 1, 1, 0, 0, 0));
        // 2000-01-01 00:00:00 UTC = 946_684_800.
        assert_eq!(epoch_to_ymdhms(946_684_800), (2000, 1, 1, 0, 0, 0));
        // 2024-02-29 00:00:00 UTC = 1_709_164_800 (leap day).
        assert_eq!(epoch_to_ymdhms(1_709_164_800), (2024, 2, 29, 0, 0, 0));
        // 2024-03-01 00:00:00 UTC = 1_709_251_200 (day after leap).
        assert_eq!(epoch_to_ymdhms(1_709_251_200), (2024, 3, 1, 0, 0, 0));
    }

    #[test]
    fn pack_writes_rfc3339_timestamp() {
        let tmp = tempfile::tempdir().unwrap();
        let wasm_path = tmp.path().join("plugin.wasm");
        std::fs::write(&wasm_path, fake_wasm(b"x")).unwrap();
        let out_path = tmp.path().join("art.tar.gz");
        let m = pack(
            &PackInputs {
                name: "p",
                version: "0.0.1",
                description: "",
                license: "AGPL-3.0-only",
                hooks: vec![],
                wasm_path: &wasm_path,
                signature_path: None,
            },
            &out_path,
        )
        .unwrap();
        // Expect "YYYY-MM-DDTHH:MM:SSZ" — 20 chars exactly.
        assert_eq!(m.packed_at.len(), 20, "got {}", m.packed_at);
        assert!(m.packed_at.ends_with('Z'));
    }
}
