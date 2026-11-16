//! PKCS#11 key provider (KMS milestone, K1): Ed25519 signing keys held in an
//! HSM and reached through its PKCS#11 module (a vendor HSM in production,
//! SoftHSM2 for development and CI). The private key never leaves the HSM:
//! Kavach finds it by label, checks how it was made, and asks the HSM to
//! sign (`CKM_EDDSA`, pure Ed25519, RFC 8032).
//!
//! - **Before a key is used** ([`Pkcs11KeyProvider::open`]) it must be an
//!   Ed25519 key that may sign. With [`Pkcs11Config::require_hsm_generated`]
//!   (the default outside development) it must also be sensitive, always
//!   sensitive, not extractable and never extractable: together these show
//!   it was generated inside the HSM and has never been readable.
//! - **The public key is proven at startup:** the HSM signs a probe message
//!   and the signature is checked with the public key read from the token.
//! - **Sessions are pooled.** A call that fails because the session or the
//!   device went away logs in again on a fresh session, finds the keys again
//!   and retries once; anything else fails closed (`Unavailable`), which the
//!   callers turn into a BLOCK.
//! - **Blocking calls stay off the async workers:** [`KeyProvider::sign`]
//!   runs on the blocking pool; the synchronous [`EvidenceSigner`] (called
//!   inside the evidence commit) uses `block_in_place` on a multi-threaded
//!   runtime.
//! - **Every call after startup has a deadline**
//!   ([`Pkcs11KeyProvider::with_call_timeout`], default
//!   [`DEFAULT_CALL_TIMEOUT`]): a sign or health check that has not answered
//!   by then fails closed (`Unavailable`) and the caller stops waiting. The
//!   call itself cannot be cancelled: it keeps its thread and its session
//!   until the token answers.

use std::collections::BTreeMap;
use std::fmt;
use std::future::Future;
use std::path::PathBuf;
use std::sync::{mpsc, Arc, Mutex, RwLock};
use std::time::Duration;

use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::error::{Error as CkError, RvError};
use cryptoki::mechanism::eddsa::{EddsaParams, EddsaSignatureScheme};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, AttributeType, KeyType, ObjectClass, ObjectHandle};
use cryptoki::session::{Session, UserType};
use cryptoki::slot::Slot;
use cryptoki::types::AuthPin;
use ed25519_dalek::{Signature, VerifyingKey};
use kavach_ports::agent_evidence::EvidenceSigner;
use kavach_ports::{KeyAlgorithm, KeyProvider, PortError, PublicKey};

/// `CKA_EC_PARAMS` for Ed25519: the curve OID (RFC 8410) in DER...
const ED25519_OID: &[u8] = &[0x06, 0x03, 0x2B, 0x65, 0x70];
/// ...or the curve name as a DER PrintableString (PKCS#11 3.0 allows both).
const ED25519_NAME: &[u8] = b"\x13\x0cedwards25519";
/// Signed and verified once per key at startup.
const PROBE: &[u8] = b"kavach pkcs11 key provider: startup probe";

/// How long a sign or health call may wait for the token before it fails
/// closed, unless [`Pkcs11KeyProvider::with_call_timeout`] says otherwise.
pub const DEFAULT_CALL_TIMEOUT: Duration = Duration::from_secs(5);

/// What to open. The PIN comes from a file the operator protects (K2), never
/// from the command line or the environment.
pub struct Pkcs11Config {
    /// Path of the vendor's PKCS#11 module (`.so`).
    pub module: PathBuf,
    /// The token holding the keys.
    pub token_label: String,
    /// The token's user PIN.
    pub pin: AuthPin,
    /// Key ids to load; each is the label of one private and one public key.
    pub key_ids: Vec<String>,
    /// Sessions kept open for reuse.
    pub max_sessions: usize,
    /// Refuse keys that could have been imported or read out.
    pub require_hsm_generated: bool,
}

impl fmt::Debug for Pkcs11Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Pkcs11Config")
            .field("module", &self.module)
            .field("token_label", &self.token_label)
            .field("key_ids", &self.key_ids)
            .field("max_sessions", &self.max_sessions)
            .field("require_hsm_generated", &self.require_hsm_generated)
            .finish_non_exhaustive()
    }
}

#[derive(Clone)]
struct Key {
    private: ObjectHandle,
    public: PublicKey,
}

struct Inner {
    pkcs11: Pkcs11,
    token_label: String,
    /// Found again by label on every reconnect: an HSM may renumber slots.
    slot: RwLock<Slot>,
    pin: AuthPin,
    key_ids: Vec<String>,
    max_sessions: usize,
    require_hsm_generated: bool,
    sessions: Mutex<Vec<Session>>,
    keys: RwLock<BTreeMap<String, Key>>,
    /// Held while logging in again, so one failure does not start many.
    reconnecting: Mutex<()>,
}

/// Signing keys in a PKCS#11 token. Cheap to clone; clones share sessions.
#[derive(Clone)]
pub struct Pkcs11KeyProvider {
    inner: Arc<Inner>,
    call_timeout: Duration,
}

impl fmt::Debug for Pkcs11KeyProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Pkcs11KeyProvider")
            .field("key_ids", &self.inner.key_ids)
            .field("call_timeout", &self.call_timeout)
            .finish_non_exhaustive()
    }
}

fn unavailable(what: &str, err: impl fmt::Display) -> PortError {
    PortError::unavailable(format!("HSM: {what}: {err}"))
}

fn timed_out(what: &str, deadline: Duration) -> PortError {
    PortError::unavailable(format!(
        "HSM: {what}: no answer within {} ms",
        deadline.as_millis()
    ))
}

/// Runs a blocking HSM call on another thread and waits at most `deadline`
/// for it. On expiry the caller gets `Unavailable`; the call keeps its
/// thread until the token answers, and its result is dropped.
fn blocking_with_deadline<T: Send + 'static>(
    what: &str,
    deadline: Duration,
    call: impl FnOnce() -> Result<T, PortError> + Send + 'static,
) -> Result<T, PortError> {
    let (tx, rx) = mpsc::sync_channel(1);
    let job = move || {
        // The receiver is gone once the caller stopped waiting.
        let _ = tx.send(call());
    };
    let runtime = tokio::runtime::Handle::try_current().ok();
    match &runtime {
        Some(handle) => {
            handle.spawn_blocking(job);
        }
        None => {
            std::thread::Builder::new()
                .name("kavach-hsm-call".into())
                .spawn(job)
                .map_err(|e| unavailable(what, e))?;
        }
    }
    let wait = || rx.recv_timeout(deadline);
    let answer = match runtime {
        Some(handle) if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
            tokio::task::block_in_place(wait)
        }
        _ => wait(),
    };
    match answer {
        Ok(result) => result,
        Err(mpsc::RecvTimeoutError::Timeout) => Err(timed_out(what, deadline)),
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            Err(unavailable(what, "the call ended without an answer"))
        }
    }
}

/// The async form of [`blocking_with_deadline`]: the call runs on the
/// blocking pool and the caller stops waiting after `deadline`.
async fn spawn_with_deadline<T: Send + 'static>(
    what: &str,
    deadline: Duration,
    call: impl FnOnce() -> Result<T, PortError> + Send + 'static,
) -> Result<T, PortError> {
    match tokio::time::timeout(deadline, tokio::task::spawn_blocking(call)).await {
        Ok(joined) => joined.map_err(|e| unavailable(what, e))?,
        Err(_) => Err(timed_out(what, deadline)),
    }
}

/// Errors after which a fresh session (and fresh object handles) may work.
fn is_reconnectable(err: &CkError) -> bool {
    matches!(
        err,
        CkError::Pkcs11(
            RvError::SessionHandleInvalid
                | RvError::SessionClosed
                | RvError::DeviceRemoved
                | RvError::DeviceError
                | RvError::TokenNotPresent
                | RvError::UserNotLoggedIn
                | RvError::CryptokiNotInitialized
                | RvError::ObjectHandleInvalid
                | RvError::KeyHandleInvalid
                | RvError::SlotIdInvalid
                | RvError::TokenNotRecognized,
            _
        )
    )
}

fn initialize(pkcs11: &Pkcs11) -> Result<(), PortError> {
    match pkcs11.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK)) {
        Ok(()) | Err(CkError::Pkcs11(RvError::CryptokiAlreadyInitialized, _)) => Ok(()),
        Err(e) => Err(unavailable("initialise module", e)),
    }
}

fn find_slot(pkcs11: &Pkcs11, token_label: &str) -> Result<Slot, PortError> {
    let slots = pkcs11
        .get_slots_with_token()
        .map_err(|e| unavailable("list slots", e))?;
    let mut found = Vec::new();
    for slot in slots {
        let info = pkcs11
            .get_token_info(slot)
            .map_err(|e| unavailable("read token info", e))?;
        if info.label().trim_end() == token_label {
            found.push(slot);
        }
    }
    match found.as_slice() {
        [slot] => Ok(*slot),
        [] => Err(PortError::unavailable(format!(
            "HSM: no token labelled {token_label:?}"
        ))),
        _ => Err(PortError::unavailable(format!(
            "HSM: several tokens labelled {token_label:?}"
        ))),
    }
}

/// The 32-byte Ed25519 point from `CKA_EC_POINT`: raw, or inside a DER
/// OCTET STRING (as PKCS#11 3.0 specifies).
fn ed25519_point(raw: &[u8]) -> Option<[u8; 32]> {
    match raw {
        [0x04, 0x20, rest @ ..] if rest.len() == 32 => rest.try_into().ok(),
        _ if raw.len() == 32 => raw.try_into().ok(),
        _ => None,
    }
}

/// Why a private key is refused, if it is. `strict` adds the checks that
/// show the key was generated inside the HSM and was never readable.
fn private_key_problems(attributes: &[Attribute], strict: bool) -> Vec<&'static str> {
    let mut key_type = None;
    let mut params = None;
    let mut flags = BTreeMap::new();
    for attribute in attributes {
        match attribute {
            Attribute::KeyType(t) => key_type = Some(*t),
            Attribute::EcParams(p) => params = Some(p.clone()),
            Attribute::Sign(v) => drop(flags.insert("sign", *v)),
            Attribute::Sensitive(v) => drop(flags.insert("sensitive", *v)),
            Attribute::AlwaysSensitive(v) => drop(flags.insert("always_sensitive", *v)),
            Attribute::Extractable(v) => drop(flags.insert("extractable", *v)),
            Attribute::NeverExtractable(v) => drop(flags.insert("never_extractable", *v)),
            _ => {}
        }
    }
    let mut problems = Vec::new();
    if key_type != Some(KeyType::EC_EDWARDS) {
        problems.push("not an Edwards-curve key");
    }
    if !matches!(params.as_deref(), Some(p) if p == ED25519_OID || p == ED25519_NAME) {
        problems.push("not on Ed25519");
    }
    if flags.get("sign") != Some(&true) {
        problems.push("may not sign (CKA_SIGN)");
    }
    if strict {
        if flags.get("sensitive") != Some(&true) {
            problems.push("not sensitive (CKA_SENSITIVE)");
        }
        if flags.get("always_sensitive") != Some(&true) {
            problems.push("not always sensitive (CKA_ALWAYS_SENSITIVE): it was readable once");
        }
        if flags.get("extractable") != Some(&false) {
            problems.push("extractable (CKA_EXTRACTABLE)");
        }
        if flags.get("never_extractable") != Some(&true) {
            problems.push(
                "not never-extractable (CKA_NEVER_EXTRACTABLE): it was imported or exportable once",
            );
        }
    }
    problems
}

/// Exactly one object of `class` labelled `kid`.
fn find_one(session: &Session, class: ObjectClass, kid: &str) -> Result<ObjectHandle, PortError> {
    let found = session
        .find_objects(&[
            Attribute::Class(class),
            Attribute::Label(kid.as_bytes().to_vec()),
        ])
        .map_err(|e| unavailable("find key", e))?;
    match found.as_slice() {
        [one] => Ok(*one),
        [] => Err(PortError::rejected(format!(
            "HSM has no {class} labelled {kid}"
        ))),
        _ => Err(PortError::rejected(format!(
            "HSM has several {class} objects labelled {kid}"
        ))),
    }
}

impl Inner {
    /// A fresh session, logged in as the user (once per application; later
    /// sessions share the login).
    fn open_session(&self) -> Result<Session, CkError> {
        let slot = *self.slot.read().map_err(|_| {
            CkError::Pkcs11(
                RvError::GeneralError,
                cryptoki::context::Function::OpenSession,
            )
        })?;
        let session = self.pkcs11.open_ro_session(slot)?;
        match session.login(UserType::User, Some(&self.pin)) {
            Ok(()) | Err(CkError::Pkcs11(RvError::UserAlreadyLoggedIn, _)) => Ok(session),
            Err(e) => Err(e),
        }
    }

    fn checkout(&self) -> Result<Session, CkError> {
        let pooled = self.sessions.lock().ok().and_then(|mut pool| pool.pop());
        match pooled {
            Some(session) => Ok(session),
            None => self.open_session(),
        }
    }

    fn checkin(&self, session: Session) {
        if let Ok(mut pool) = self.sessions.lock() {
            if pool.len() < self.max_sessions {
                pool.push(session);
            }
        }
    }

    /// Finds, checks and proves one key.
    fn load_key(&self, session: &Session, kid: &str) -> Result<Key, PortError> {
        let private = find_one(session, ObjectClass::PRIVATE_KEY, kid)?;
        let public = find_one(session, ObjectClass::PUBLIC_KEY, kid)?;
        let attributes = session
            .get_attributes(
                private,
                &[
                    AttributeType::KeyType,
                    AttributeType::EcParams,
                    AttributeType::Sign,
                    AttributeType::Sensitive,
                    AttributeType::AlwaysSensitive,
                    AttributeType::Extractable,
                    AttributeType::NeverExtractable,
                ],
            )
            .map_err(|e| unavailable("read key attributes", e))?;
        let problems = private_key_problems(&attributes, self.require_hsm_generated);
        if !problems.is_empty() {
            return Err(PortError::rejected(format!(
                "HSM key {kid} refused: {}",
                problems.join("; ")
            )));
        }
        let point = session
            .get_attributes(public, &[AttributeType::EcPoint])
            .map_err(|e| unavailable("read public key", e))?
            .into_iter()
            .find_map(|a| match a {
                Attribute::EcPoint(p) => ed25519_point(&p),
                _ => None,
            })
            .ok_or_else(|| {
                PortError::rejected(format!("HSM key {kid}: no Ed25519 public point"))
            })?;
        let verifying = VerifyingKey::from_bytes(&point)
            .map_err(|e| PortError::rejected(format!("HSM key {kid}: public key: {e}")))?;
        let probe = session
            .sign(&eddsa(), private, PROBE)
            .map_err(|e| unavailable("sign the startup probe", e))?;
        let signature = Signature::from_slice(&probe)
            .map_err(|e| PortError::rejected(format!("HSM key {kid}: probe signature: {e}")))?;
        verifying.verify_strict(PROBE, &signature).map_err(|_| {
            PortError::rejected(format!(
                "HSM key {kid}: the public key does not verify the private key's signature"
            ))
        })?;
        Ok(Key {
            private,
            public: PublicKey {
                kid: kid.to_string(),
                algorithm: KeyAlgorithm::Ed25519,
                bytes: point,
            },
        })
    }

    fn load_keys(&self) -> Result<(), PortError> {
        let session = self.open_session().map_err(|e| unavailable("log in", e))?;
        let mut keys = BTreeMap::new();
        for kid in &self.key_ids {
            keys.insert(kid.clone(), self.load_key(&session, kid)?);
        }
        *self
            .keys
            .write()
            .map_err(|_| PortError::unavailable("HSM key table poisoned"))? = keys;
        self.checkin(session);
        Ok(())
    }

    /// Initialises the module if needed, finds the token by label, logs in
    /// and finds the keys.
    fn start(&self) -> Result<(), PortError> {
        initialize(&self.pkcs11)?;
        let slot = find_slot(&self.pkcs11, &self.token_label)?;
        *self
            .slot
            .write()
            .map_err(|_| PortError::unavailable("HSM slot lock poisoned"))? = slot;
        self.load_keys()
    }

    /// Drops every pooled session, logs in again and finds the keys again.
    /// If that fails, the module's own state may be stale (an HSM that went
    /// away and came back), so it is shut down and started once more. Each
    /// failed call tries again; nothing needs a restart.
    fn reconnect(&self) -> Result<(), PortError> {
        let _one_at_a_time = self
            .reconnecting
            .lock()
            .map_err(|_| PortError::unavailable("HSM reconnect lock poisoned"))?;
        if let Ok(mut pool) = self.sessions.lock() {
            pool.clear();
        }
        tracing::warn!("HSM: reconnecting after a session or device error");
        if self.start().is_ok() {
            return Ok(());
        }
        if let Err(e) = self.pkcs11.clone().finalize() {
            tracing::debug!("HSM: finalize before restarting the module: {e}");
        }
        self.start()
    }

    fn private_handle(&self, kid: &str) -> Result<ObjectHandle, PortError> {
        self.keys
            .read()
            .map_err(|_| PortError::unavailable("HSM key table poisoned"))?
            .get(kid)
            .map(|k| k.private)
            .ok_or_else(|| PortError::rejected(format!("unknown signing key {kid}")))
    }

    fn try_sign(&self, handle: ObjectHandle, message: &[u8]) -> Result<Vec<u8>, CkError> {
        let session = self.checkout()?;
        let signature = session.sign(&eddsa(), handle, message)?;
        self.checkin(session);
        Ok(signature)
    }

    /// Signs on the calling thread (it blocks on the HSM).
    fn sign_blocking(&self, kid: &str, message: &[u8]) -> Result<Vec<u8>, PortError> {
        let handle = self.private_handle(kid)?;
        match self.try_sign(handle, message) {
            Ok(signature) => Ok(signature),
            Err(e) if is_reconnectable(&e) => {
                self.reconnect()?;
                self.try_sign(self.private_handle(kid)?, message)
                    .map_err(|e| unavailable("sign after reconnecting", e))
            }
            Err(e) => Err(unavailable("sign", e)),
        }
    }

    /// Checks a session on the calling thread (it blocks on the HSM).
    fn health_blocking(&self) -> Result<(), PortError> {
        let check = || -> Result<(), CkError> {
            let session = self.checkout()?;
            session.get_session_info()?;
            self.checkin(session);
            Ok(())
        };
        match check() {
            Ok(()) => Ok(()),
            Err(e) if is_reconnectable(&e) => {
                self.reconnect()?;
                check().map_err(|e| unavailable("health after reconnecting", e))
            }
            Err(e) => Err(unavailable("health", e)),
        }
    }
}

fn eddsa() -> Mechanism<'static> {
    Mechanism::Eddsa(EddsaParams::new(EddsaSignatureScheme::Pure))
}

/// Reads a token PIN from a file only its owner can read (as key files
/// are): one line, surrounding whitespace ignored. The PIN is never logged.
pub fn read_pin_file(path: &std::path::Path) -> Result<AuthPin, PortError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path)
            .map_err(|e| PortError::unavailable(format!("HSM PIN file {}: {e}", path.display())))?
            .permissions()
            .mode();
        if mode & 0o077 != 0 {
            return Err(PortError::rejected(format!(
                "HSM PIN file {} must not be accessible by group or others (mode {:o})",
                path.display(),
                mode & 0o777
            )));
        }
    }
    let text = std::fs::read_to_string(path)
        .map_err(|e| PortError::unavailable(format!("HSM PIN file {}: {e}", path.display())))?;
    let pin = text.trim();
    if pin.is_empty() {
        return Err(PortError::invalid(format!(
            "HSM PIN file {} is empty",
            path.display()
        )));
    }
    Ok(AuthPin::new(pin.into()))
}

impl Pkcs11KeyProvider {
    /// Loads the module, logs in to the token and loads, checks and proves
    /// every configured key. Fails if any key is missing or refused.
    pub fn open(config: Pkcs11Config) -> Result<Self, PortError> {
        if config.key_ids.is_empty() {
            return Err(PortError::invalid("HSM: no key ids configured"));
        }
        let pkcs11 = Pkcs11::new(&config.module).map_err(|e| {
            unavailable(
                &format!("load PKCS#11 module {}", config.module.display()),
                e,
            )
        })?;
        initialize(&pkcs11)?;
        let slot = find_slot(&pkcs11, &config.token_label)?;
        let inner = Inner {
            pkcs11,
            token_label: config.token_label,
            slot: RwLock::new(slot),
            pin: config.pin,
            key_ids: config.key_ids,
            max_sessions: config.max_sessions.max(1),
            require_hsm_generated: config.require_hsm_generated,
            sessions: Mutex::new(Vec::new()),
            keys: RwLock::new(BTreeMap::new()),
            reconnecting: Mutex::new(()),
        };
        inner.load_keys()?;
        Ok(Self {
            inner: Arc::new(inner),
            call_timeout: DEFAULT_CALL_TIMEOUT,
        })
    }

    /// Sets how long each later sign or health call may wait for the token
    /// (startup in [`Self::open`] has no deadline). Clones made afterwards,
    /// and signers from [`Self::evidence_signer`], use it too.
    #[must_use]
    pub fn with_call_timeout(mut self, timeout: Duration) -> Self {
        self.call_timeout = timeout;
        self
    }

    /// How long a sign or health call may wait for the token.
    #[must_use]
    pub fn call_timeout(&self) -> Duration {
        self.call_timeout
    }

    /// The loaded keys' public halves.
    pub fn public_keys(&self) -> Result<Vec<PublicKey>, PortError> {
        Ok(self
            .inner
            .keys
            .read()
            .map_err(|_| PortError::unavailable("HSM key table poisoned"))?
            .values()
            .map(|k| k.public.clone())
            .collect())
    }

    /// Whether the HSM answers now, within the call timeout; reconnects
    /// once if it went away. For `/v1/runtime` (K2).
    pub fn health(&self) -> Result<(), PortError> {
        let inner = Arc::clone(&self.inner);
        blocking_with_deadline("health", self.call_timeout, move || inner.health_blocking())
    }

    /// A synchronous signer for evidence records and checkpoints.
    pub fn evidence_signer(&self, kid: &str) -> Result<Pkcs11EvidenceSigner, PortError> {
        self.inner.private_handle(kid)?;
        Ok(Pkcs11EvidenceSigner {
            provider: self.clone(),
            kid: kid.to_string(),
        })
    }
}

impl KeyProvider for Pkcs11KeyProvider {
    fn sign(
        &self,
        kid: &str,
        message: &[u8],
    ) -> impl Future<Output = Result<Vec<u8>, PortError>> + Send {
        let inner = Arc::clone(&self.inner);
        let deadline = self.call_timeout;
        let (kid, message) = (kid.to_string(), message.to_vec());
        async move {
            spawn_with_deadline("sign", deadline, move || {
                inner.sign_blocking(&kid, &message)
            })
            .await
        }
    }

    fn public_key(&self, kid: &str) -> impl Future<Output = Result<PublicKey, PortError>> + Send {
        let key = self
            .inner
            .keys
            .read()
            .map_err(|_| PortError::unavailable("HSM key table poisoned"))
            .and_then(|keys| {
                keys.get(kid)
                    .map(|k| k.public.clone())
                    .ok_or_else(|| PortError::rejected(format!("unknown signing key {kid}")))
            });
        std::future::ready(key)
    }
}

/// [`EvidenceSigner`] over an HSM key. Signing blocks on the HSM, for at
/// most the provider's call timeout; on a multi-threaded runtime it tells
/// the runtime first (`block_in_place`), so other tasks move off this worker
/// meanwhile.
#[derive(Clone)]
pub struct Pkcs11EvidenceSigner {
    provider: Pkcs11KeyProvider,
    kid: String,
}

impl fmt::Debug for Pkcs11EvidenceSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Pkcs11EvidenceSigner")
            .field("kid", &self.kid)
            .finish_non_exhaustive()
    }
}

impl EvidenceSigner for Pkcs11EvidenceSigner {
    fn key_id(&self) -> &str {
        &self.kid
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, PortError> {
        let inner = Arc::clone(&self.provider.inner);
        let (kid, message) = (self.kid.clone(), message.to_vec());
        blocking_with_deadline("sign", self.provider.call_timeout, move || {
            inner.sign_blocking(&kid, &message)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attrs(strict_ok: bool) -> Vec<Attribute> {
        vec![
            Attribute::KeyType(KeyType::EC_EDWARDS),
            Attribute::EcParams(ED25519_OID.to_vec()),
            Attribute::Sign(true),
            Attribute::Sensitive(true),
            Attribute::AlwaysSensitive(strict_ok),
            Attribute::Extractable(false),
            Attribute::NeverExtractable(strict_ok),
        ]
    }

    #[test]
    fn a_generated_key_passes_and_an_imported_one_only_when_not_strict() {
        assert!(private_key_problems(&attrs(true), true).is_empty());
        let imported = private_key_problems(&attrs(false), true);
        assert_eq!(imported.len(), 2, "{imported:?}");
        assert!(private_key_problems(&attrs(false), false).is_empty());
    }

    #[test]
    fn the_curve_and_the_sign_flag_are_always_required() {
        let mut other = attrs(true);
        other[1] = Attribute::EcParams(vec![0x06, 0x03, 0x2B, 0x65, 0x71]); // Ed448
        other[2] = Attribute::Sign(false);
        let problems = private_key_problems(&other, false);
        assert!(problems.contains(&"not on Ed25519"), "{problems:?}");
        assert!(
            problems.contains(&"may not sign (CKA_SIGN)"),
            "{problems:?}"
        );
        let mut named = attrs(true);
        named[1] = Attribute::EcParams(ED25519_NAME.to_vec());
        assert!(private_key_problems(&named, true).is_empty());
        // A missing attribute counts as not satisfied.
        assert!(!private_key_problems(&attrs(true)[..2], true).is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn the_pin_file_must_be_owner_only_and_not_empty() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("kavach-pin-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("pin");
        std::fs::write(&path, "1234\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_pin_file(&path).is_err(), "group-readable");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(read_pin_file(&path).is_ok());
        std::fs::write(&path, "  \n").unwrap();
        assert!(read_pin_file(&path).is_err(), "empty");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A token that never answers: the call blocks until the test lets go.
    fn hung_token() -> (
        mpsc::Sender<()>,
        impl FnOnce() -> Result<u8, PortError> + Send,
    ) {
        let (release, hold) = mpsc::channel::<()>();
        (release, move || {
            let _ = hold.recv();
            Ok(7)
        })
    }

    /// Runs `check` on its own thread and fails the test (instead of hanging
    /// it) if `check` has not returned within `limit`.
    fn finishes_within<T: Send + 'static>(
        limit: Duration,
        check: impl FnOnce() -> T + Send + 'static,
    ) -> T {
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(check());
        });
        rx.recv_timeout(limit)
            .expect("the HSM call did not give up at its deadline")
    }

    #[test]
    fn a_hung_synchronous_call_fails_closed_at_its_deadline() {
        let (release, call) = hung_token();
        let deadline = Duration::from_millis(200);
        let started = std::time::Instant::now();
        let result = finishes_within(Duration::from_secs(5), move || {
            blocking_with_deadline("sign", deadline, call)
        });
        let err = result.expect_err("a hung token must not produce a signature");
        assert_eq!(err.class, kavach_ports::ErrorClass::Unavailable, "{err:?}");
        assert!(err.message.contains("no answer within 200 ms"), "{err:?}");
        assert!(started.elapsed() >= deadline);
        drop(release);
    }

    #[test]
    fn a_hung_call_inside_the_runtime_fails_closed_at_its_deadline() {
        let result = finishes_within(Duration::from_secs(5), || {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .unwrap();
            let (release, call) = hung_token();
            let (release2, call2) = hung_token();
            let out = runtime.block_on(async move {
                let deadline = Duration::from_millis(200);
                let asynchronous = spawn_with_deadline("sign", deadline, call).await;
                // The synchronous signer, as the evidence commit calls it.
                let synchronous =
                    tokio::spawn(async move { blocking_with_deadline("sign", deadline, call2) })
                        .await
                        .unwrap();
                (asynchronous, synchronous)
            });
            drop((release, release2));
            runtime.shutdown_background();
            out
        });
        for err in [result.0.unwrap_err(), result.1.unwrap_err()] {
            assert_eq!(err.class, kavach_ports::ErrorClass::Unavailable, "{err:?}");
        }
    }

    #[test]
    fn a_call_that_answers_in_time_returns_its_result() {
        let deadline = Duration::from_secs(5);
        assert_eq!(
            blocking_with_deadline("sign", deadline, || Ok(3)).unwrap(),
            3
        );
        let failed = blocking_with_deadline::<u8>("sign", deadline, || {
            Err(PortError::unavailable("token removed"))
        });
        assert!(failed.unwrap_err().message.contains("token removed"));
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let answered = runtime.block_on(spawn_with_deadline("sign", deadline, || Ok(4)));
        assert_eq!(answered.unwrap(), 4);
    }

    #[test]
    fn public_points_are_read_raw_or_wrapped() {
        let point = [7u8; 32];
        let mut wrapped = vec![0x04, 0x20];
        wrapped.extend_from_slice(&point);
        assert_eq!(ed25519_point(&point), Some(point));
        assert_eq!(ed25519_point(&wrapped), Some(point));
        assert_eq!(ed25519_point(&wrapped[..20]), None);
        assert_eq!(ed25519_point(&[0x04, 0x21, 0]), None);
    }
}
