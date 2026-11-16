//! The OIDC test double from `tests/support/oidc_double.rs`, as a local
//! development identity provider for the console sign-in (ADR-018), e.g.
//! for the Playwright checks. The Rust tests use the same code in-process.
//!
//! ```text
//! cargo run -p kavach-api --example oidc_double -- \
//!     --client-secret-file /tmp/kavach-dev/console.secret \
//!     --jwks-out /tmp/kavach-dev/jwks.json \
//!     [--listen 127.0.0.1:9400] [--client-id kavach-console] \
//!     [--audience kavach-api] [--sub dev-admin] [--groups admins,operators] \
//!     [--users users.json] [--also-trust bundle/kavach/jwks.json] [--pick]
//! ```
//!
//! `--users` lists more users, `{"users": [{"sub": "...", "groups": [...]}]}`.
//! A sign-in signs in the one whose `sub` the browser names in the
//! `oidc_double_user` cookie at the double's origin, or the `--sub` user
//! when it names none; a name not in the file is refused.
//!
//! `--pick` is for a person at a browser (`scripts/demo.sh`): each sign-in
//! shows a page listing the `--sub` user and the `--users`, and signs in
//! the one picked. The cookie is then not read.
//!
//! `--also-trust` adds another JWKS's public keys to the `--jwks-out` file,
//! for tokens another signer minted with this double's issuer (a
//! `kavach-dev generate --issuer` bundle's agent and operator tokens), so
//! one `kavach-api` accepts both. Only the file changes; the double's own
//! `/jwks` serves its key alone.
//!
//! If the client secret file does not exist, a random secret is written
//! to it, readable by the owner only. Every run uses a new signing key and
//! rewrites the JWKS file. The double prints the `kavach-api` flags to use
//! (never the secret) and runs until it is stopped.
//!
//! **A test tool only, for loopback** (it refuses any other `--listen`
//! address). It signs in whoever asks as a
//! configured user, accepts any `redirect_uri`, and keeps everything in
//! memory. Never point a deployment at it. Its issuer is a plain-HTTP
//! loopback URL, so `kavach-api` needs `--insecure-dev` to use it.

#[path = "../tests/support/oidc_double.rs"]
mod oidc_double;

use std::io::Write as _;
use std::path::{Path, PathBuf};

use std::collections::HashMap;

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
    users: Option<PathBuf>,
    also_trust: Option<PathBuf>,
    pick: bool,
}

fn usage(problem: &str) -> ! {
    eprintln!(
        "oidc_double: {problem}\nusage: oidc_double --client-secret-file <path> --jwks-out <path> \
         [--listen 127.0.0.1:9400] [--client-id kavach-console] [--audience kavach-api] \
         [--sub dev-admin] [--groups admins] [--users users.json] \
         [--also-trust jwks.json] [--pick]"
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
        users: None,
        also_trust: None,
        pick: false,
    };
    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        if flag == "--pick" {
            args.pick = true;
            continue;
        }
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
            "--users" => args.users = Some(value.into()),
            "--also-trust" => args.also_trust = Some(value.into()),
            other => usage(&format!("unknown flag {other}")),
        }
    }
    if args.client_secret_file.as_os_str().is_empty() || args.jwks_out.as_os_str().is_empty() {
        usage("--client-secret-file and --jwks-out are required");
    }
    args
}

/// The `--users` file: `{"users": [{"sub": "...", "groups": ["..."]}]}`,
/// by `sub`.
fn users(path: &Path) -> HashMap<String, TestUser> {
    let text = std::fs::read_to_string(path)
        .unwrap_or_else(|e| usage(&format!("cannot read the users file: {e}")));
    let file: serde_json::Value = serde_json::from_str(&text)
        .unwrap_or_else(|e| usage(&format!("the users file is not JSON: {e}")));
    let Some(list) = file.get("users").and_then(serde_json::Value::as_array) else {
        usage("the users file needs a \"users\" array");
    };
    let mut users = HashMap::new();
    for entry in list {
        let sub = entry.get("sub").and_then(serde_json::Value::as_str);
        let groups = entry.get("groups").and_then(serde_json::Value::as_array);
        let (Some(sub), Some(groups)) = (sub, groups) else {
            usage("each user needs a \"sub\" string and a \"groups\" array");
        };
        let groups: Option<Vec<String>> = groups
            .iter()
            .map(|g| g.as_str().map(str::to_string))
            .collect();
        let Some(groups) = groups else {
            usage("groups must be strings");
        };
        let user = TestUser {
            sub: sub.to_string(),
            groups,
        };
        if sub.is_empty() || users.insert(sub.to_string(), user).is_some() {
            usage("each user needs a distinct, non-empty \"sub\"");
        }
    }
    users
}

/// The double's JWKS, plus the keys of the `--also-trust` file; a `kid`
/// that appears twice is refused.
fn published_keys(own: serde_json::Value, also: Option<&Path>) -> serde_json::Value {
    let Some(path) = also else { return own };
    let text = std::fs::read_to_string(path)
        .unwrap_or_else(|e| usage(&format!("cannot read the --also-trust file: {e}")));
    let other: serde_json::Value = serde_json::from_str(&text)
        .unwrap_or_else(|e| usage(&format!("the --also-trust file is not JSON: {e}")));
    let mut keys = own["keys"].as_array().cloned().unwrap_or_default();
    let Some(extra) = other.get("keys").and_then(serde_json::Value::as_array) else {
        usage("the --also-trust file needs a \"keys\" array");
    };
    for key in extra {
        if keys
            .iter()
            .any(|k| k.get("kid").is_some() && k.get("kid") == key.get("kid"))
        {
            usage("a --also-trust key has the kid of a key already listed");
        }
        keys.push(key.clone());
    }
    serde_json::json!({ "keys": keys })
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
    let named = args.users.as_deref().map(users).unwrap_or_default();
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
    let mut subs: Vec<String> = named.keys().cloned().collect();
    subs.sort();
    double.set(|b| {
        b.users = named;
        b.pick = args.pick;
    });
    let keys = published_keys(double.jwks(), args.also_trust.as_deref());
    std::fs::write(&args.jwks_out, keys.to_string()).expect("write the JWKS file");

    println!(
        "OIDC test double at {url}, signing in {sub} (groups: {groups}).\n\
         Start kavach-api with:\n  \
         --insecure-dev --oidc-issuer {url} --oidc-audience {audience} \
         --oidc-jwks-file {jwks} --console-client-id {client} \
         --console-client-secret-file {secret} \
         --console-redirect-uri http://127.0.0.1:<port>/auth/callback{others}",
        url = double.issuer,
        sub = args.sub,
        groups = args.groups.join(","),
        audience = args.audience,
        jwks = args.jwks_out.display(),
        client = args.client_id,
        secret = args.client_secret_file.display(),
        others = if args.pick {
            format!(
                "\nEach sign-in asks who to sign in as: {}",
                std::iter::once(args.sub.clone())
                    .chain(subs.iter().filter(|s| **s != args.sub).cloned())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        } else if subs.is_empty() {
            String::new()
        } else {
            format!(
                "\nOther users, by the oidc_double_user cookie: {}",
                subs.join(", ")
            )
        },
    );
    std::future::pending::<()>().await;
}
