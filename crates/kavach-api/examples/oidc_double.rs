//! The OIDC test double from `tests/support/oidc_double.rs`, as a local
//! development identity provider for the console sign-in (ADR-018), e.g.
//! for the Playwright checks. The Rust tests use the same code in-process.
//!
//! ```text
//! cargo run -p kavach-api --example oidc_double -- \
//!     --client-secret-file /tmp/kavach-dev/console.secret \
//!     --jwks-out /tmp/kavach-dev/jwks.json \
//!     [--listen 127.0.0.1:9400] [--client-id kavach-console] \
//!     [--audience kavach-api] [--sub dev-admin] [--groups admins,operators]
//! ```
//!
//! If the client secret file does not exist, a random secret is written
//! to it, readable by the owner only. Every run uses a new signing key and
//! rewrites the JWKS file. The double prints the `kavach-api` flags to use
//! (never the secret) and runs until it is stopped.
//!
//! **A test tool only, for loopback** (it refuses any other `--listen`
//! address). It signs in whoever asks as the one
//! configured user, accepts any `redirect_uri`, and keeps everything in
//! memory. Never point a deployment at it. Its issuer is a plain-HTTP
//! loopback URL, so `kavach-api` needs `--insecure-dev` to use it.

#[path = "../tests/support/oidc_double.rs"]
mod oidc_double;

use std::io::Write as _;
use std::path::{Path, PathBuf};

use oidc_double::{DoubleConfig, OidcDouble, TestUser};
use ring::rand::{SecureRandom, SystemRandom};

struct Args {
    listen: String,
    client_id: String,
    client_secret_file: PathBuf,
    jwks_out: PathBuf,
    audience: String,
    sub: String,
    groups: Vec<String>,
}

fn usage(problem: &str) -> ! {
    eprintln!(
        "oidc_double: {problem}\nusage: oidc_double --client-secret-file <path> --jwks-out <path> \
         [--listen 127.0.0.1:9400] [--client-id kavach-console] [--audience kavach-api] \
         [--sub dev-admin] [--groups admins]"
    );
    std::process::exit(2);
}

fn parse() -> Args {
    let mut args = Args {
        listen: "127.0.0.1:9400".into(),
        client_id: "kavach-console".into(),
        client_secret_file: PathBuf::new(),
        jwks_out: PathBuf::new(),
        audience: "kavach-api".into(),
        sub: "dev-admin".into(),
        groups: vec!["admins".into()],
    };
    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        let value = it
            .next()
            .unwrap_or_else(|| usage(&format!("{flag} needs a value")));
        match flag.as_str() {
            "--listen" => args.listen = value,
            "--client-id" => args.client_id = value,
            "--client-secret-file" => args.client_secret_file = value.into(),
            "--jwks-out" => args.jwks_out = value.into(),
            "--audience" => args.audience = value,
            "--sub" => args.sub = value,
            "--groups" => {
                args.groups = value
                    .split(',')
                    .filter(|g| !g.is_empty())
                    .map(str::to_string)
                    .collect();
            }
            other => usage(&format!("unknown flag {other}")),
        }
    }
    if args.client_secret_file.as_os_str().is_empty() || args.jwks_out.as_os_str().is_empty() {
        usage("--client-secret-file and --jwks-out are required");
    }
    args
}

fn random_bytes<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    SystemRandom::new().fill(&mut bytes).expect("random");
    bytes
}

/// Reads the client secret, or writes a new random one, owner-only.
fn client_secret(path: &Path) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    if let Ok(text) = std::fs::read_to_string(path) {
        let secret = text.trim().to_string();
        if secret.is_empty() {
            usage("the client secret file is empty");
        }
        return secret;
    }
    let secret: String = random_bytes::<24>()
        .iter()
        .flat_map(|b| {
            [
                char::from(HEX[usize::from(b >> 4)]),
                char::from(HEX[usize::from(b & 0x0F)]),
            ]
        })
        .collect();
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .unwrap_or_else(|e| usage(&format!("cannot create the client secret file: {e}")));
    writeln!(file, "{secret}").expect("write the client secret");
    secret
}

#[tokio::main]
async fn main() {
    let args = parse();
    let secret = client_secret(&args.client_secret_file);
    let listen: std::net::SocketAddr = args
        .listen
        .parse()
        .unwrap_or_else(|_| usage("--listen must be an address such as 127.0.0.1:9400"));
    if !listen.ip().is_loopback() {
        usage("--listen must be a loopback address; the double signs in anyone who asks");
    }
    let seed = random_bytes::<32>();
    let kid = "oidc-double-1";
    let double = OidcDouble::start(DoubleConfig {
        issuer: None,
        seed,
        kid: kid.into(),
        client_id: args.client_id.clone(),
        client_secret: secret,
        audience: args.audience.clone(),
        user: TestUser {
            sub: args.sub.clone(),
            groups: args.groups.clone(),
        },
        listen,
    })
    .await;
    std::fs::write(&args.jwks_out, double.jwks().to_string()).expect("write the JWKS file");

    println!(
        "OIDC test double at {url}, signing in {sub} (groups: {groups}).\n\
         Start kavach-api with:\n  \
         --insecure-dev --oidc-issuer {url} --oidc-audience {audience} \
         --oidc-jwks-file {jwks} --console-client-id {client} \
         --console-client-secret-file {secret} \
         --console-redirect-uri http://127.0.0.1:<port>/auth/callback",
        url = double.issuer,
        sub = args.sub,
        groups = args.groups.join(","),
        audience = args.audience,
        jwks = args.jwks_out.display(),
        client = args.client_id,
        secret = args.client_secret_file.display(),
    );
    std::future::pending::<()>().await;
}
