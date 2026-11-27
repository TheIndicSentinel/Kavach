//! Provider secret lookup port (ADR-015). Configuration carries an opaque
//! reference, never the provider credential itself.

use std::future::Future;
use std::pin::Pin;

use crate::{PortError, TokenSecret};

/// A boxed future keeps the secret-store port object-safe for runtime adapter
/// selection (local file in development, OpenBao in a deployment).
pub type ProviderSecretFuture<'a> =
    Pin<Box<dyn Future<Output = Result<TokenSecret, PortError>> + Send + 'a>>;

/// Resolves a provider credential only for the operation that needs it.
pub trait ProviderSecretStore: Send + Sync {
    fn read<'a>(&'a self, reference: &'a str) -> ProviderSecretFuture<'a>;
}
