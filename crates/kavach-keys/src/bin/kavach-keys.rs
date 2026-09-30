//! Key and pack-signing tool.
//!
//! ```text
//! kavach-keys generate   --dir <keys> --kid <kid>
//! kavach-keys public-key --dir <keys> --kid <kid>        # prints a trusted-signers entry
//! kavach-keys sign-pack  --dir <keys> --kid <kid> --pack <pack.yaml>   # writes <pack.yaml>.sig
//! kavach-keys verify-pack --signers <signers.json> --pack <pack.yaml>
//! ```

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use kavach_keys::{
    sign_pack, signature_path, verify_pack_file, LocalFileKeyProvider, TrustedSigners,
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
    }
    Ok(())
}
