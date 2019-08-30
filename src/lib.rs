//! Hyper SSL support via OpenSSL.
#![warn(missing_docs)]
#![doc(html_root_url = "https://docs.rs/hyper-openssl/0.7")]
#![feature(type_alias_impl_trait)]

extern crate antidote;
extern crate bytes;
extern crate futures;
extern crate hyper;
extern crate linked_hash_set;
pub extern crate openssl;
extern crate tokio_io;
extern crate tokio_openssl;

#[macro_use]
extern crate lazy_static;

#[cfg(test)]
extern crate tokio;

use antidote::Mutex;
use bytes::{Buf, BufMut};
use hyper::client::connect::{Connect, Connected, Destination};
#[cfg(feature = "runtime")]
use hyper::client::HttpConnector;
use openssl::error::ErrorStack;
use openssl::ex_data::Index;
use openssl::ssl::{
    ConnectConfiguration, Ssl, SslConnector, SslConnectorBuilder, SslMethod, SslSessionCacheMode,
};
use std::error::Error;
use std::fmt::Debug;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio_io::{AsyncRead, AsyncWrite};
use tokio_openssl::SslStream;

use cache::{SessionCache, SessionKey};

mod cache;
#[cfg(test)]
mod test;

lazy_static! {
    // The unwrap here isn't great but this only fails on OOM
    static ref KEY_INDEX: Index<Ssl, SessionKey> = Ssl::new_ex_index().unwrap();
}

#[derive(Clone)]
struct Inner {
    ssl: SslConnector,
    cache: Arc<Mutex<SessionCache>>,
    callback: Option<
        Arc<
            dyn Fn(&mut ConnectConfiguration, &Destination) -> Result<(), ErrorStack> + Sync + Send,
        >,
    >,
}

impl Inner {
    fn setup_ssl(&self, destination: &Destination) -> Result<ConnectConfiguration, ErrorStack> {
        let mut conf = self.ssl.configure()?;

        if let Some(ref callback) = self.callback {
            callback(&mut conf, destination)?;
        }

        let key = SessionKey {
            host: destination.host().to_string(),
            port: destination.port().unwrap_or(443),
        };

        if let Some(session) = self.cache.lock().get(&key) {
            unsafe {
                conf.set_session(&session)?;
            }
        }

        conf.set_ex_data(*KEY_INDEX, key);

        Ok(conf)
    }
}

/// A Connector using OpenSSL to support `http` and `https` schemes.
#[derive(Clone)]
pub struct HttpsConnector<T> {
    http: T,
    inner: Inner,
}

#[cfg(feature = "runtime")]
impl HttpsConnector<HttpConnector> {
    /// Creates a a new `HttpsConnector` using default settings.
    ///
    /// The Hyper `HttpConnector` is used to perform the TCP socket connection. ALPN is configured to support both
    /// HTTP/2 and HTTP/1.1.
    ///
    /// Requires the `runtime` Cargo feature.
    pub fn new() -> Result<HttpsConnector<HttpConnector>, ErrorStack> {
        let mut http = HttpConnector::new();
        http.enforce_http(false);
        let mut ssl = SslConnector::builder(SslMethod::tls())?;
        // avoid unused_mut warnings when building against OpenSSL 1.0.1
        ssl = ssl;

        #[cfg(ossl102)]
        ssl.set_alpn_protos(b"\x02h2\x08http/1.1")?;

        HttpsConnector::with_connector(http, ssl)
    }
}

impl<T> HttpsConnector<T>
where
    T: Connect,
    T::Transport: Debug + Sync + Send,
{
    /// Creates a new `HttpsConnector`.
    ///
    /// The session cache configuration of `ssl` will be overwritten.
    pub fn with_connector(
        http: T,
        mut ssl: SslConnectorBuilder,
    ) -> Result<HttpsConnector<T>, ErrorStack> {
        let cache = Arc::new(Mutex::new(SessionCache::new()));

        ssl.set_session_cache_mode(SslSessionCacheMode::CLIENT);

        ssl.set_new_session_callback({
            let cache = cache.clone();
            move |ssl, session| {
                if let Some(key) = ssl.ex_data(*KEY_INDEX) {
                    cache.lock().insert(key.clone(), session);
                }
            }
        });

        ssl.set_remove_session_callback({
            let cache = cache.clone();
            move |_, session| cache.lock().remove(session)
        });

        Ok(HttpsConnector {
            http,
            inner: Inner {
                ssl: ssl.build(),
                cache,
                callback: None,
            },
        })
    }

    /// Registers a callback which can customize the configuration of each connection.
    pub fn set_callback<F>(&mut self, callback: F)
    where
        F: Fn(&mut ConnectConfiguration, &Destination) -> Result<(), ErrorStack>
            + 'static
            + Sync
            + Send,
    {
        self.inner.callback = Some(Arc::new(callback));
    }
}

impl<T> Connect for HttpsConnector<T>
where
    T: Connect,
    T::Transport: Debug + Sync + Send,
{
    type Transport = MaybeHttpsStream<T::Transport>;

    type Error = Box<dyn Error + Sync + Send>;

    type Future = ConnectFuture<T>;

    fn connect(&self, destination: Destination) -> Self::Future {
        let tls_setup = if destination.scheme() == "https" {
            Some((self.inner.clone(), destination.clone()))
        } else {
            None
        };

        let conn = self.http.connect(destination);

        // TODO: why does Connect requires its future to be Unpin? For now lets just pin box it.
        Box::pin(connect::<T>(conn, tls_setup))
    }
}

type ConnectFuture<T: Connect> = impl Future<
        Output = Result<(MaybeHttpsStream<T::Transport>, Connected), Box<dyn Error + Sync + Send>>,
    > + Unpin
    + Send;

async fn connect<T>(
    conn: T::Future,
    tls_setup: Option<(Inner, Destination)>,
) -> Result<(MaybeHttpsStream<T::Transport>, Connected), Box<dyn Error + Sync + Send>>
where
    T: Connect,
    T::Transport: Debug + Sync + Send,
{
    let (stream, mut connected) = match conn.await {
        Ok((stream, connected)) => (stream, connected),
        Err(error) => return Err(error.into()),
    };
    match tls_setup {
        Some((inner, destination)) => {
            let ssl = inner.setup_ssl(&destination)?;
            let handshake = tokio_openssl::connect(ssl, destination.host(), stream);
            let stream = handshake.await?;

            // avoid unused_mut warnings on OpenSSL 1.0.1
            connected = connected;

            #[cfg(ossl102)]
            {
                if let Some(b"h2") = stream.ssl().selected_alpn_protocol() {
                    connected = connected.negotiated_h2();
                }
            }
            return Ok((MaybeHttpsStream::Https(stream), connected));
        }
        None => return Ok((MaybeHttpsStream::Http(stream), connected)),
    }
}

/// A stream which may be wrapped with TLS.
pub enum MaybeHttpsStream<T> {
    /// A raw HTTP stream.
    Http(T),
    /// An SSL-wrapped HTTP stream.
    Https(SslStream<T>),
}

impl<T> AsyncRead for MaybeHttpsStream<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    unsafe fn prepare_uninitialized_buffer(&self, buf: &mut [u8]) -> bool {
        match *self {
            MaybeHttpsStream::Http(ref s) => s.prepare_uninitialized_buffer(buf),
            MaybeHttpsStream::Https(ref s) => s.prepare_uninitialized_buffer(buf),
        }
    }

    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        match *self {
            MaybeHttpsStream::Http(ref mut s) => Pin::new(s).poll_read(cx, buf),
            MaybeHttpsStream::Https(ref mut s) => Pin::new(s).poll_read(cx, buf),
        }
    }

    fn poll_read_buf<B: BufMut>(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut B,
    ) -> Poll<io::Result<usize>>
    where
        B: BufMut,
    {
        match *self {
            MaybeHttpsStream::Http(ref mut s) => Pin::new(s).poll_read_buf(cx, buf),
            MaybeHttpsStream::Https(ref mut s) => Pin::new(s).poll_read_buf(cx, buf),
        }
    }
}

impl<T> AsyncWrite for MaybeHttpsStream<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match *self {
            MaybeHttpsStream::Http(ref mut s) => Pin::new(s).poll_write(cx, buf),
            MaybeHttpsStream::Https(ref mut s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        match *self {
            MaybeHttpsStream::Http(ref mut s) => Pin::new(s).poll_flush(cx),
            MaybeHttpsStream::Https(ref mut s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        match *self {
            MaybeHttpsStream::Http(ref mut s) => Pin::new(s).poll_shutdown(cx),
            MaybeHttpsStream::Https(ref mut s) => Pin::new(s).poll_shutdown(cx),
        }
    }

    fn poll_write_buf<B: Buf>(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut B,
    ) -> Poll<io::Result<usize>>
    where
        Self: Sized,
    {
        match *self {
            MaybeHttpsStream::Http(ref mut s) => Pin::new(s).poll_write_buf(cx, buf),
            MaybeHttpsStream::Https(ref mut s) => Pin::new(s).poll_write_buf(cx, buf),
        }
    }
}
