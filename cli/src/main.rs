//! `helios-plugin` CLI — pack / inspect / verify WASM plugin artefacts.
//!
//! ```text
//! helios-plugin pack    --wasm <path> --name X --version 1.0 \
//!                       --hooks pre_query,post_query [--sig <path>] \
//!                       --out <path>
//!
//! helios-plugin inspect <artefact.tar.gz>
//!
//! helios-plugin verify  <artefact.tar.gz> --trust-root <dir>
//! ```
//!
//! The artefact format is a `.tar.gz` containing `manifest.json` +
//! `plugin.wasm` + optional `plugin.sig`. See `manifest.rs` for the
//! manifest schema.

mod artefact;
mod manifest;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(version, about = "Pack and verify HeliosProxy WASM plugin artefacts")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Pack a `.wasm` plus optional `.sig` into a portable
    /// `.tar.gz` artefact with a JSON manifest.
    Pack {
        /// Path to the plugin .wasm file.
        #[arg(long)]
        wasm: PathBuf,

        /// Plugin name (e.g. "helios-plugin-cost-governor").
        #[arg(long)]
        name: String,

        /// Plugin version (semver recommended).
        #[arg(long)]
        version: String,

        /// One-line description.
        #[arg(long, default_value = "")]
        description: String,

        /// SPDX license identifier.
        #[arg(long, default_value = "Apache-2.0")]
        license: String,

        /// Comma-separated list of hooks the plugin implements.
        #[arg(long, value_delimiter = ',')]
        hooks: Vec<String>,

        /// Optional `.sig` file (base64 Ed25519 signature).
        #[arg(long)]
        sig: Option<PathBuf>,

        /// Output path for the artefact.
        #[arg(long)]
        out: PathBuf,
    },

    /// Print the manifest of an existing artefact.
    Inspect {
        artefact: PathBuf,
    },

    /// Verify the signature of an artefact against a trust root
    /// (directory of `*.pub` files, base64 raw Ed25519 keys).
    Verify {
        artefact: PathBuf,
        #[arg(long)]
        trust_root: PathBuf,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Pack {
            wasm,
            name,
            version,
            description,
            license,
            hooks,
            sig,
            out,
        } => {
            let inputs = artefact::PackInputs {
                name: &name,
                version: &version,
                description: &description,
                license: &license,
                hooks,
                wasm_path: &wasm,
                signature_path: sig.as_deref(),
            };
            let manifest = artefact::pack(&inputs, &out).context("pack")?;
            println!(
                "packed {} v{}\n  out: {}\n  wasm sha256: {}\n  signed:      {}",
                manifest.name,
                manifest.version,
                out.display(),
                manifest.wasm_sha256,
                manifest.signature_sha256.is_some(),
            );
        }
        Cmd::Inspect { artefact: path } => {
            let unpacked = artefact::unpack(&path).context("unpack")?;
            let json = serde_json::to_string_pretty(&unpacked.manifest)?;
            println!("{}", json);
        }
        Cmd::Verify { artefact: path, trust_root } => {
            let unpacked = artefact::unpack(&path).context("unpack")?;
            let label = artefact::verify(&unpacked, &trust_root)
                .context("verify")?;
            println!("OK — signed by {}", label);
        }
    }
    Ok(())
}
