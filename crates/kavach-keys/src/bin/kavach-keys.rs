//! Key and pack-signing tool.
//!
//! ```text
//! kavach-keys generate   --dir <keys> --kid <kid>
//! kavach-keys public-key --dir <keys> --kid <kid>        # prints a trusted-signers entry
//! kavach-keys sign-pack  --dir <keys> --kid <kid> --pack <pack.yaml>   # writes <pack.yaml>.sig
//! kavach-keys verify-pack --signers <signers.json> --pack <pack.yaml>
//! kavach-keys sign-model  --dir <keys> --kid <kid> --model <model.yaml> # writes <model.yaml>.sig
//! kavach-keys verify-model --signers <signers.json> --model <model.yaml>
//! ```
//!
//! Model signers need `"roles": ["model"]` in the trusted-signers file.

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use kavach_keys::{
    sign_model, sign_pack, sign_tool_registry, signature_path, verify_model_file, verify_pack_file,
    verify_tool_registry_file, LocalFileKeyProvider, ModelIdentity, TrustedSigners,
};
use kavach_ports::KeyProvider;

#[derive(Parser)]
#[command(name = "kavach-keys", about = "Kavach key management and pack signing")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate a new Ed25519 key (owner-only file).
    Generate {
        #[arg(long)]
        dir: PathBuf,
        #[arg(long)]
        kid: String,
    },
    /// Print the public key as a trusted-signers JSON entry.
    PublicKey {
        #[arg(long)]
        dir: PathBuf,
        #[arg(long)]
        kid: String,
    },
    /// Sign a pack file; writes `<pack>.sig`.
    SignPack {
        #[arg(long)]
        dir: PathBuf,
        #[arg(long)]
        kid: String,
        #[arg(long)]
        pack: PathBuf,
    },
    /// Verify `<pack>.sig` against a trusted-signers file.
    VerifyPack {
        #[arg(long)]
        signers: PathBuf,
        #[arg(long)]
        pack: PathBuf,
    },
    /// Sign a model record file (id, version and digest); writes `<model>.sig`.
    SignModel {
        #[arg(long)]
        dir: PathBuf,
        #[arg(long)]
        kid: String,
        #[arg(long)]
        model: PathBuf,
    },
    /// Verify `<model>.sig` against a trusted-signers file (model role).
    VerifyModel {
        #[arg(long)]
        signers: PathBuf,
        #[arg(long)]
        model: PathBuf,
    },
    /// Sign an agent tool registry file; writes `<registry>.sig`.
    SignTools {
        #[arg(long)]
        dir: PathBuf,
        #[arg(long)]
        kid: String,
        #[arg(long)]
        registry: PathBuf,
    },
    /// Verify `<registry>.sig` against a trusted-signers file (tool role).
    VerifyTools {
        #[arg(long)]
        signers: PathBuf,
        #[arg(long)]
        registry: PathBuf,
    },
}

/// The fields of a model record that its signature covers.
#[derive(serde::Deserialize)]
struct ModelHeader {
    model_id: String,
    version: String,
}

fn read_model(path: &std::path::Path) -> Result<(ModelHeader, String), Box<dyn std::error::Error>> {
    let bytes = std::fs::read(path)?;
    let header: ModelHeader = serde_yaml::from_slice(&bytes)?;
    Ok((header, kavach_policy::pack_digest(&bytes)))
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    match Cli::parse().command {
        Command::Generate { dir, kid } => {
            let public = LocalFileKeyProvider::new(dir).create_key(&kid)?;
            println!("generated {kid} (public key {})", hex::encode(public.bytes));
        }
        Command::PublicKey { dir, kid } => {
            let public = LocalFileKeyProvider::new(dir).public_key(&kid).await?;
            println!(
                "{}",
                serde_json::json!({ "kid": public.kid, "public_key": hex::encode(public.bytes) })
            );
        }
        Command::SignPack { dir, kid, pack } => {
            let provider = LocalFileKeyProvider::new(dir);
            let signature = sign_pack(&provider, &kid, &pack).await?;
            let out = signature_path(&pack);
            std::fs::write(&out, serde_json::to_string_pretty(&signature)? + "\n")?;
            println!("wrote {} ({})", out.display(), signature.pack_sha256);
        }
        Command::VerifyPack { signers, pack } => {
            let trusted = TrustedSigners::from_file(&signers)?;
            let digest = kavach_policy::pack_digest(&std::fs::read(&pack)?);
            verify_pack_file(&pack, &digest, &trusted)?;
            println!("ok: {} {digest}", pack.display());
        }
        Command::SignModel { dir, kid, model } => {
            let (header, digest) = read_model(&model)?;
            let provider = LocalFileKeyProvider::new(dir);
            let identity = ModelIdentity {
                model_id: &header.model_id,
                model_version: &header.version,
                model_sha256: &digest,
            };
            let signature = sign_model(&provider, &kid, identity).await?;
            let out = signature_path(&model);
            std::fs::write(&out, serde_json::to_string_pretty(&signature)? + "\n")?;
            println!(
                "wrote {} ({} {} {digest})",
                out.display(),
                header.model_id,
                header.version
            );
        }
        Command::VerifyModel { signers, model } => {
            let (header, digest) = read_model(&model)?;
            let trusted = TrustedSigners::from_file(&signers)?;
            let identity = ModelIdentity {
                model_id: &header.model_id,
                model_version: &header.version,
                model_sha256: &digest,
            };
            verify_model_file(&model, identity, &trusted)?;
            println!("ok: {} {} {digest}", header.model_id, header.version);
        }
        Command::SignTools { dir, kid, registry } => {
            let digest = kavach_policy::pack_digest(&std::fs::read(&registry)?);
            let provider = LocalFileKeyProvider::new(dir);
            let signature = sign_tool_registry(&provider, &kid, &digest).await?;
            let out = signature_path(&registry);
            std::fs::write(&out, serde_json::to_string_pretty(&signature)? + "\n")?;
            println!("wrote {} ({digest})", out.display());
        }
        Command::VerifyTools { signers, registry } => {
            let trusted = TrustedSigners::from_file(&signers)?;
            let digest = kavach_policy::pack_digest(&std::fs::read(&registry)?);
            verify_tool_registry_file(&registry, &digest, &trusted)?;
            println!("ok: {} {digest}", registry.display());
        }
    }
    Ok(())
}
