//! Listener limits (roadmap 1.2): how long a client may take, and how many
//! requests a listener works on at once.
//!
//! Every listener (operator HTTP, agent, system of record, gRPC) applies:
//!
//! - **TLS handshake timeout:** a handshake not finished within
//!   [`ListenerLimits::tls_handshake_timeout`] closes the connection.
//! - **Header read and idle timeout:** a connection with no request in
//!   progress must deliver a complete request head within
//!   [`ListenerLimits::header_read_timeout`] of being accepted (TLS
//!   handshake included) or of its last response bytes being written;
//!   otherwise it is closed. A client that sends a few bytes at a time
//!   does not extend this deadline. A write that makes no progress for the
//!   same time (a client that stops reading) also closes the connection.
//! - **Request timeout:** a request that has not produced its response
//!   within [`ListenerLimits::request_timeout`] (reading its body included)
//!   is answered `503` with an RFC 9457 problem (`unavailable`, with
//!   `request_id` and `Retry-After`); gRPC answers `CANCELLED`. The handler
//!   is dropped at that point. Work a handler runs synchronously (policy
//!   evaluation and the evidence write) cannot be interrupted: a response
//!   it produces late is still the real one, never a partial decision.
//! - **In-flight cap:** at most [`ListenerLimits::max_in_flight`] requests
//!   per listener are being handled at once. A request over the cap is
//!   answered `503` (`unavailable`, `Retry-After`) at once (gRPC:
//!   `UNAVAILABLE`); it is never queued.
//!
//! No setting turns a limit off: each has bounds, and startup refuses a
//! value outside them.

use std::fmt;
use std::future::Future;
use std::io;
use std::ops::RangeInclusive;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use axum::extract::{ConnectInfo, Request, State};
use axum::http::{HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::Semaphore;
use tokio::time::{Instant, Sleep};

use crate::correlation::REQUEST_ID_HEADER;
use crate::problem::Problem;

/// Default request timeout, seconds.
pub const DEFAULT_REQUEST_TIMEOUT_SECONDS: u64 = 30;
/// Accepted request timeouts, seconds.
pub const REQUEST_TIMEOUT_SECONDS: RangeInclusive<u64> = 1..=300;
/// Default header read (and idle) timeout, seconds.
pub const DEFAULT_HEADER_READ_TIMEOUT_SECONDS: u64 = 10;
/// Accepted header read timeouts, seconds.
pub const HEADER_READ_TIMEOUT_SECONDS: RangeInclusive<u64> = 1..=120;
/// Default TLS handshake timeout, seconds.
pub const DEFAULT_TLS_HANDSHAKE_TIMEOUT_SECONDS: u64 = 10;
/// Accepted TLS handshake timeouts, seconds.
pub const TLS_HANDSHAKE_TIMEOUT_SECONDS: RangeInclusive<u64> = 1..=60;
/// Default cap on requests handled at once, per listener.
pub const DEFAULT_MAX_IN_FLIGHT_REQUESTS: u64 = 256;
/// Accepted in-flight caps.
pub const MAX_IN_FLIGHT_REQUESTS: RangeInclusive<u64> = 1..=65_536;

/// Default HSM call timeout, milliseconds
/// (`kavach_keys_pkcs11::DEFAULT_CALL_TIMEOUT`).
pub const DEFAULT_HSM_TIMEOUT_MS: u64 = 5_000;
/// Accepted HSM call timeouts, milliseconds.
pub const HSM_TIMEOUT_MS: RangeInclusive<u64> = 100..=60_000;

/// The limits one listener applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ListenerLimits {
    pub request_timeout: Duration,
    pub header_read_timeout: Duration,
    pub tls_handshake_timeout: Duration,
    pub max_in_flight: usize,
}

impl Default for ListenerLimits {
    fn default() -> Self {
        Self {
            request_timeout: Duration::from_secs(DEFAULT_REQUEST_TIMEOUT_SECONDS),
            header_read_timeout: Duration::from_secs(DEFAULT_HEADER_READ_TIMEOUT_SECONDS),
            tls_handshake_timeout: Duration::from_secs(DEFAULT_TLS_HANDSHAKE_TIMEOUT_SECONDS),
            max_in_flight: usize::try_from(DEFAULT_MAX_IN_FLIGHT_REQUESTS).unwrap_or(usize::MAX),
        }
    }
}

fn within(name: &str, value: u64, range: &RangeInclusive<u64>, unit: &str) -> Result<(), String> {
    if range.contains(&value) {
        Ok(())
    } else {
        Err(format!(
            "{name} must be between {} and {} {unit} (got {value})",
            range.start(),
            range.end()
        ))
    }
}

impl ListenerLimits {
    /// Builds limits from settings, refusing any value outside its bounds.
    pub fn from_settings(
        request_timeout_seconds: u64,
        header_read_timeout_seconds: u64,
        tls_handshake_timeout_seconds: u64,
        max_in_flight: u64,
    ) -> Result<Self, String> {
        let limits = Self {
            request_timeout: Duration::from_secs(request_timeout_seconds),
            header_read_timeout: Duration::from_secs(header_read_timeout_seconds),
            tls_handshake_timeout: Duration::from_secs(tls_handshake_timeout_seconds),
            max_in_flight: usize::try_from(max_in_flight).unwrap_or(usize::MAX),
        };
        limits.validate()?;
        Ok(limits)
    }

    /// Refuses a value outside its bounds (none can be zero, so none can
    /// turn a limit off or refuse every request).
    pub fn validate(&self) -> Result<(), String> {
        within(
            "the request timeout",
            self.request_timeout.as_secs(),
            &REQUEST_TIMEOUT_SECONDS,
            "seconds",
        )?;
        within(
            "the header read timeout",
            self.header_read_timeout.as_secs(),
            &HEADER_READ_TIMEOUT_SECONDS,
            "seconds",
        )?;
        within(
            "the TLS handshake timeout",
            self.tls_handshake_timeout.as_secs(),
            &TLS_HANDSHAKE_TIMEOUT_SECONDS,
            "seconds",
        )?;
        within(
            "the in-flight request cap",
            u64::try_from(self.max_in_flight).unwrap_or(u64::MAX),
            &MAX_IN_FLIGHT_REQUESTS,
            "requests",
        )?;
        // Sub-second parts are not settings: refuse them rather than round.
        for d in [
            self.request_timeout,
            self.header_read_timeout,
            self.tls_handshake_timeout,
        ] {
            if d.subsec_nanos() != 0 {
                return Err("listener timeouts are whole seconds".into());
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Per-connection state: is a request in progress, and since when idle.

struct ConnState {
    in_flight: usize,
    idle_since: Instant,
    /// The connection task, woken when its last request finishes so that
    /// it arms the idle deadline.
    waker: Option<Waker>,
}

/// One accepted connection's request state. Cheap to clone.
#[derive(Clone)]
pub struct ConnHandle(Arc<Mutex<ConnState>>);

impl fmt::Debug for ConnHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ConnHandle")
    }
}

impl ConnHandle {
    fn new() -> Self {
        Self(Arc::new(Mutex::new(ConnState {
            in_flight: 0,
            idle_since: Instant::now(),
            waker: None,
        })))
    }

    fn state(&self) -> std::sync::MutexGuard<'_, ConnState> {
        // A poisoned lock only means a panic elsewhere; the counters are
        // still meaningful.
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Marks a request on this connection as in progress until the guard
    /// drops.
    #[must_use]
    pub fn begin(&self) -> ConnGuard {
        self.state().in_flight += 1;
        ConnGuard(self.clone())
    }

    /// When the connection must have delivered a request head, or `None`
    /// while a request is in progress (then `waker` is woken when it ends).
    fn idle_since(&self, waker: &Waker) -> Option<Instant> {
        let mut state = self.state();
        if state.in_flight > 0 {
            match &state.waker {
                Some(w) if w.will_wake(waker) => {}
                _ => state.waker = Some(waker.clone()),
            }
            None
        } else {
            Some(state.idle_since)
        }
    }
}

/// A request in progress on a connection.
pub struct ConnGuard(ConnHandle);

impl Drop for ConnGuard {
    fn drop(&mut self) {
        let waker = {
            let mut state = self.0.state();
            state.in_flight = state.in_flight.saturating_sub(1);
            if state.in_flight > 0 {
                return;
            }
            state.idle_since = Instant::now();
            state.waker.take()
        };
        if let Some(waker) = waker {
            waker.wake();
        }
    }
}

// ---------------------------------------------------------------------------
// The IO wrapper that enforces the header read / idle deadline.

fn timed_out(what: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, what)
}

/// A connection's stream with the header read / idle deadline and the
/// stalled-write deadline (see the module docs).
pub struct DeadlineIo<I> {
    inner: I,
    conn: ConnHandle,
    timeout: Duration,
    /// When response bytes were last written.
    last_write: Option<Instant>,
    /// The armed idle deadline and its timer.
    idle: Option<(Instant, Pin<Box<Sleep>>)>,
    /// Armed while a write cannot make progress.
    stalled: Option<Pin<Box<Sleep>>>,
}

impl<I> fmt::Debug for DeadlineIo<I> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeadlineIo")
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

impl<I> DeadlineIo<I> {
    /// Wraps a freshly accepted stream; its idle clock starts now.
    pub fn new(inner: I, timeout: Duration) -> Self {
        Self {
            inner,
            conn: ConnHandle::new(),
            timeout,
            last_write: None,
            idle: None,
            stalled: None,
        }
    }

    /// The connection's request state (request handlers mark requests in
    /// progress through it).
    #[must_use]
    pub fn conn(&self) -> &ConnHandle {
        &self.conn
    }

    /// `Pending` until the idle deadline passes (then an error), or while a
    /// request is in progress.
    fn poll_idle<T>(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<T>> {
        let Some(idle_since) = self.conn.idle_since(cx.waker()) else {
            self.idle = None;
            return Poll::Pending;
        };
        let since = self.last_write.map_or(idle_since, |w| w.max(idle_since));
        let deadline = since + self.timeout;
        if !matches!(&self.idle, Some((at, _)) if *at == deadline) {
            self.idle = Some((deadline, Box::pin(tokio::time::sleep_until(deadline))));
        }
        let Some((_, timer)) = self.idle.as_mut() else {
            return Poll::Pending;
        };
        match timer.as_mut().poll(cx) {
            Poll::Ready(()) => Poll::Ready(Err(timed_out(
                "no complete request within the header read timeout",
            ))),
            Poll::Pending => Poll::Pending,
        }
    }

    /// Called when a write is `Pending`: an error once no progress was
    /// possible for the timeout.
    fn poll_stalled<T>(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<T>> {
        let timeout = self.timeout;
        let timer = self
            .stalled
            .get_or_insert_with(|| Box::pin(tokio::time::sleep(timeout)));
        match timer.as_mut().poll(cx) {
            Poll::Ready(()) => Poll::Ready(Err(timed_out(
                "the client did not read the response within the timeout",
            ))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn wrote(&mut self, n: usize) {
        self.stalled = None;
        if n > 0 {
            self.last_write = Some(Instant::now());
        }
    }
}

impl<I: AsyncRead + Unpin> AsyncRead for DeadlineIo<I> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_read(cx, buf) {
            Poll::Ready(result) => Poll::Ready(result),
            Poll::Pending => this.poll_idle(cx),
        }
    }
}

impl<I: AsyncWrite + Unpin> AsyncWrite for DeadlineIo<I> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_write(cx, buf) {
            Poll::Ready(Ok(n)) => {
                this.wrote(n);
                Poll::Ready(Ok(n))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => this.poll_stalled(cx),
        }
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_write_vectored(cx, bufs) {
            Poll::Ready(Ok(n)) => {
                this.wrote(n);
                Poll::Ready(Ok(n))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => this.poll_stalled(cx),
        }
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_flush(cx) {
            Poll::Ready(result) => {
                this.stalled = None;
                Poll::Ready(result)
            }
            Poll::Pending => this.poll_stalled(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_shutdown(cx) {
            Poll::Ready(result) => Poll::Ready(result),
            Poll::Pending => this.poll_stalled(cx),
        }
    }
}

/// gRPC reads the connection state from the request extensions.
impl<I> tonic::transport::server::Connected for DeadlineIo<I> {
    type ConnectInfo = ConnHandle;

    fn connect_info(&self) -> ConnHandle {
        self.conn.clone()
    }
}

// ---------------------------------------------------------------------------
// Plain HTTP: an axum listener that wraps each connection.

/// A TCP listener whose connections carry the header read deadline.
#[derive(Debug)]
pub struct LimitedListener {
    inner: tokio::net::TcpListener,
    header_read_timeout: Duration,
}

impl LimitedListener {
    #[must_use]
    pub fn new(inner: tokio::net::TcpListener, header_read_timeout: Duration) -> Self {
        Self {
            inner,
            header_read_timeout,
        }
    }
}

/// Waits after an accept error that is not about one connection (out of
/// file descriptors, say), so the loop does not spin.
pub(crate) async fn accept_error_pause(err: &io::Error) {
    if matches!(
        err.kind(),
        io::ErrorKind::ConnectionRefused
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
    ) {
        return;
    }
    tracing::warn!(error = %err, "accepting a connection failed; retrying in 1 s");
    tokio::time::sleep(Duration::from_secs(1)).await;
}

impl axum::serve::Listener for LimitedListener {
    type Io = DeadlineIo<tokio::net::TcpStream>;
    type Addr = std::net::SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            match self.inner.accept().await {
                Ok((stream, addr)) => {
                    return (DeadlineIo::new(stream, self.header_read_timeout), addr);
                }
                Err(e) => accept_error_pause(&e).await,
            }
        }
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        self.inner.local_addr()
    }
}

impl axum::extract::connect_info::Connected<axum::serve::IncomingStream<'_, LimitedListener>>
    for ConnHandle
{
    fn connect_info(stream: axum::serve::IncomingStream<'_, LimitedListener>) -> Self {
        stream.io().conn().clone()
    }
}

// ---------------------------------------------------------------------------
// TLS HTTP: an acceptor beneath the TLS acceptor that wraps each connection.

/// Wraps each accepted stream in [`DeadlineIo`] and hands its
/// [`ConnHandle`] to the request handlers.
#[derive(Debug, Clone, Copy)]
pub struct LimitAcceptor {
    header_read_timeout: Duration,
}

impl LimitAcceptor {
    #[must_use]
    pub fn new(header_read_timeout: Duration) -> Self {
        Self {
            header_read_timeout,
        }
    }
}

impl<I, S> axum_server::accept::Accept<I, S> for LimitAcceptor {
    type Stream = DeadlineIo<I>;
    type Service = tower_http::add_extension::AddExtension<S, ConnHandle>;
    type Future = std::future::Ready<io::Result<(Self::Stream, Self::Service)>>;

    fn accept(&self, stream: I, service: S) -> Self::Future {
        let io = DeadlineIo::new(stream, self.header_read_timeout);
        let conn = io.conn().clone();
        std::future::ready(Ok((
            io,
            tower_http::add_extension::AddExtension::new(service, conn),
        )))
    }
}

// ---------------------------------------------------------------------------
// The request layer: in-flight cap and request timeout.

/// One listener's request gate.
#[derive(Debug, Clone)]
pub struct RequestGate {
    permits: Arc<Semaphore>,
    request_timeout: Duration,
}

impl RequestGate {
    #[must_use]
    pub fn new(limits: &ListenerLimits) -> Self {
        Self {
            permits: Arc::new(Semaphore::new(limits.max_in_flight)),
            request_timeout: limits.request_timeout,
        }
    }

    /// A permit to handle one request, or `None` when the listener is at
    /// its cap (the caller refuses; nothing waits).
    #[must_use]
    pub fn try_enter(&self) -> Option<tokio::sync::OwnedSemaphorePermit> {
        Arc::clone(&self.permits).try_acquire_owned().ok()
    }

    #[must_use]
    pub fn request_timeout(&self) -> Duration {
        self.request_timeout
    }
}

/// Detail of the problem for a request over the in-flight cap.
pub const BUSY_DETAIL: &str = "too many requests in progress; retry after the time in Retry-After";
/// Detail of the problem for a request that ran out of time.
pub const TIMEOUT_DETAIL: &str =
    "the request did not complete within the request timeout; retry after the time in Retry-After";

/// Axum middleware (install with `Router::layer`, outermost): refuses a
/// request over the cap, and answers 503 for one that runs out of time.
/// It fixes the request id first, so the refusal and the handler's own
/// log line carry the same one.
pub async fn gate(State(gate): State<RequestGate>, mut req: Request, next: Next) -> Response {
    let id = crate::correlation::request_id(&req);
    if let Ok(value) = HeaderValue::from_str(&id) {
        req.headers_mut().insert(REQUEST_ID_HEADER, value);
    }
    let method = req.method().clone();
    let started = std::time::Instant::now();
    let conn = req.extensions().get::<ConnHandle>().cloned().or_else(|| {
        req.extensions()
            .get::<ConnectInfo<ConnHandle>>()
            .map(|info| info.0.clone())
    });
    let _in_progress = conn.as_ref().map(ConnHandle::begin);
    let Some(_permit) = gate.try_enter() else {
        let busy = Problem::new(StatusCode::SERVICE_UNAVAILABLE, "unavailable", BUSY_DETAIL);
        return crate::correlation::refused(
            &id,
            &method,
            "over_capacity",
            started,
            busy.into_response(),
        )
        .await;
    };
    let Ok(response) = tokio::time::timeout(gate.request_timeout, next.run(req)).await else {
        let late = Problem::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "unavailable",
            TIMEOUT_DETAIL,
        );
        return crate::correlation::refused(
            &id,
            &method,
            "timed_out",
            started,
            late.into_response(),
        )
        .await;
    };
    response
}

/// `app` with the request gate as its outermost layer.
pub fn gated(app: axum::Router, limits: &ListenerLimits) -> axum::Router {
    app.layer(axum::middleware::from_fn_with_state(
        RequestGate::new(limits),
        gate,
    ))
}

/// For gRPC: the guard and permit for one call, or the status to answer
/// (boxed, because `tonic::Status` is large).
pub(crate) fn grpc_enter(
    gate: &RequestGate,
    conn: Option<&ConnHandle>,
) -> Result<(Option<ConnGuard>, tokio::sync::OwnedSemaphorePermit), Box<tonic::Status>> {
    let in_progress = conn.map(ConnHandle::begin);
    let Some(permit) = gate.try_enter() else {
        let mut status = tonic::Status::unavailable(BUSY_DETAIL);
        status.metadata_mut().insert(
            "retry-after",
            tonic::metadata::MetadataValue::from_static("5"),
        );
        return Err(Box::new(status));
    };
    Ok((in_progress, permit))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_within_bounds_and_zero_is_refused() {
        assert!(ListenerLimits::default().validate().is_ok());
        assert!(ListenerLimits::from_settings(30, 10, 10, 256).is_ok());
        for bad in [
            ListenerLimits::from_settings(0, 10, 10, 256),
            ListenerLimits::from_settings(301, 10, 10, 256),
            ListenerLimits::from_settings(30, 0, 10, 256),
            ListenerLimits::from_settings(30, 121, 10, 256),
            ListenerLimits::from_settings(30, 10, 0, 256),
            ListenerLimits::from_settings(30, 10, 61, 256),
            ListenerLimits::from_settings(30, 10, 10, 0),
            ListenerLimits::from_settings(30, 10, 10, 65_537),
        ] {
            assert!(bad.is_err(), "{bad:?}");
        }
    }

    #[test]
    fn the_cap_refuses_instead_of_queueing() {
        let gate = RequestGate::new(&ListenerLimits {
            max_in_flight: 2,
            ..ListenerLimits::default()
        });
        let first = gate.try_enter().expect("first");
        let _second = gate.try_enter().expect("second");
        assert!(gate.try_enter().is_none(), "third is over the cap");
        drop(first);
        assert!(
            gate.try_enter().is_some(),
            "a finished request frees its place"
        );
    }
}
