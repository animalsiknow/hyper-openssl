use futures::future::{ready, FutureExt, TryFutureExt};
use futures::stream::StreamExt;
use hyper::client::HttpConnector;
use hyper::{Body, Client};
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};
use std::io::{Read, Write};
use std::thread;
use tokio::runtime::current_thread::Runtime;

use super::*;

#[test]
#[cfg(feature = "runtime")]
fn google() {
    let ssl = HttpsConnector::new().unwrap();
    let client = Client::builder().keep_alive(false).build::<_, Body>(ssl);

    let mut runtime = Runtime::new().unwrap();

    let f = client
        .get("https://www.google.com".parse().unwrap())
        .and_then(|resp| {
            assert!(resp.status().is_success(), "{}", resp.status());
            resp.into_body().for_each(|_| ready(())).map(|()| Ok(()))
        });
    runtime.block_on(f).unwrap();

    let f = client
        .get("https://www.google.com".parse().unwrap())
        .and_then(|resp| {
            assert!(resp.status().is_success(), "{}", resp.status());
            resp.into_body().for_each(|_| ready(())).map(|()| Ok(()))
        });
    runtime.block_on(f).unwrap();

    let f = client
        .get("https://www.google.com".parse().unwrap())
        .and_then(|resp| {
            assert!(resp.status().is_success(), "{}", resp.status());
            resp.into_body().for_each(|_| ready(())).map(|()| Ok(()))
        });
    runtime.block_on(f).unwrap();
}

#[test]
fn localhost() {
    let listener = ::std::net::TcpListener::bind("127.0.0.1:15410").unwrap();
    let port = listener.local_addr().unwrap().port();

    let mut ctx = SslAcceptor::mozilla_modern(SslMethod::tls()).unwrap();
    #[cfg(ossl111)]
    {
        ctx.clear_options(openssl::ssl::SslOptions::NO_TLSV1_3);
    }

    ctx.set_session_id_context(b"test").unwrap();
    ctx.set_certificate_chain_file("test/cert.pem").unwrap();
    ctx.set_private_key_file("test/key.pem", SslFiletype::PEM)
        .unwrap();
    let ctx = ctx.build();

    let thread = thread::spawn(move || {
        for _ in 0..3 {
            let stream = listener.accept().unwrap().0;
            let mut stream = ctx.accept(stream).unwrap();
            stream.read_exact(&mut [0]).unwrap();
            stream
                .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
                .unwrap();
            stream.shutdown().unwrap();
        }
    });

    let mut connector = HttpConnector::new();
    connector.enforce_http(false);
    let mut ssl = SslConnector::builder(SslMethod::tls()).unwrap();
    ssl.set_ca_file("test/cert.pem").unwrap();

    #[cfg(ossl111)]
    {
        use std::fs::File;
        use std::io::Write;

        let file = File::create("target/keyfile.log").unwrap();
        ssl.set_keylog_callback(move |_, line| {
            let _ = writeln!(&file, "{}", line);
        });
    }

    let ssl = HttpsConnector::with_connector(connector, ssl).unwrap();
    let client = Client::builder().build::<_, Body>(ssl);

    let mut runtime = Runtime::new().unwrap();

    for _ in 0..3 {
        let f = client
            .get(format!("https://localhost:{}", port).parse().unwrap())
            .and_then(|resp| {
                assert!(resp.status().is_success(), "{}", resp.status());
                resp.into_body().for_each(|_| ready(())).map(|()| Ok(()))
            });
        runtime.block_on(f).unwrap();
    }

    thread.join().unwrap();
}

#[test]
#[cfg(ossl102)]
fn alpn_h2() {
    use hyper::server::conn::Http;
    use hyper::service;
    use hyper::Response;
    use openssl::ssl::{self, AlpnError};
    use tokio::net::TcpListener;

    let mut runtime = Runtime::new().unwrap();

    let mut listener = runtime.block_on(TcpListener::bind(&"127.0.0.1:0")).unwrap();
    let port = listener.local_addr().unwrap().port();

    let mut ctx = SslAcceptor::mozilla_modern(SslMethod::tls()).unwrap();
    ctx.set_certificate_chain_file("test/cert.pem").unwrap();
    ctx.set_private_key_file("test/key.pem", SslFiletype::PEM)
        .unwrap();
    ctx.set_alpn_select_callback(|_, client| {
        ssl::select_next_proto(b"\x02h2", client).ok_or(AlpnError::NOACK)
    });
    let ctx = ctx.build();

    runtime.spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.expect("tcp accept error");
            let stream = tokio_openssl::accept(&ctx, stream).await.expect("tls accept error");
            assert_eq!(stream.ssl().selected_alpn_protocol().unwrap(), b"h2");
            Http::new().http2_only(true).serve_connection(
                stream,
                service::service_fn(|_| {
                    ready(Result::<_, Box<dyn Error + Send + Sync>>::Ok(
                        Response::new(Body::empty()),
                    ))
                }),
            ).await.expect("http error");
        }
    });

    let mut connector = HttpConnector::new();
    connector.enforce_http(false);
    let mut ssl = SslConnector::builder(SslMethod::tls()).unwrap();
    ssl.set_ca_file("test/cert.pem").unwrap();
    ssl.set_alpn_protos(b"\x02h2\x08http/1.1").unwrap();

    let ssl = HttpsConnector::with_connector(connector, ssl).unwrap();
    let client = Client::builder().build::<_, Body>(ssl);

    let f = client
        .get(format!("https://localhost:{}", port).parse().unwrap())
        .and_then(|resp| {
            assert!(resp.status().is_success(), "{}", resp.status());
            resp.into_body().for_each(|_| ready(())).map(|()| Ok(()))
        });
    runtime.block_on(f).unwrap();
}
