pub mod auth;
pub mod cors;
pub mod encryption;
pub mod error;
pub mod handlers;
pub mod policy;
pub mod quota;
pub mod router;
pub mod storage;
pub mod users;
pub mod xml;

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto;
use hyper_util::server::graceful::GracefulShutdown;
use tokio::net::TcpListener;
use tokio::sync::RwLock;

use encryption::EncryptionConfig;
use storage::Storage;
use users::UserStore;

/// Maximum time for an HTTP/1 client to send the request headers.
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Server configuration shared across all connections.
pub struct ServerConfig {
    pub storage: Arc<Storage>,
    pub user_store: Option<Arc<RwLock<UserStore>>>,
    pub admin_api_key: Option<String>,
    pub upload_ttl_secs: u64,
    pub encryption: Option<EncryptionConfig>,
}

/// Start the S3 server on the given listener with the given config.
/// Runs until the process exits.
pub async fn serve(listener: TcpListener, config: Arc<ServerConfig>) {
    serve_with_shutdown(listener, config, std::future::pending(), Duration::ZERO).await;
}

/// Start the S3 server and stop gracefully when `shutdown` resolves:
/// the listener is closed, then in-flight requests get up to `grace` to finish
/// before remaining connections are dropped.
pub async fn serve_with_shutdown(
    listener: TcpListener,
    config: Arc<ServerConfig>,
    shutdown: impl Future<Output = ()>,
    grace: Duration,
) {
    let graceful = GracefulShutdown::new();
    tokio::pin!(shutdown);

    loop {
        let (stream, _) = tokio::select! {
            conn = listener.accept() => match conn {
                Ok(conn) => conn,
                Err(e) => {
                    eprintln!("Failed to accept connection: {}", e);
                    continue;
                }
            },
            _ = &mut shutdown => break,
        };

        let config = config.clone();
        let io = TokioIo::new(stream);
        let service = service_fn(move |req| {
            let config = config.clone();
            router::route(req, config)
        });

        // Auto-negotiate HTTP/1.1 or HTTP/2 based on ALPN.
        // HTTP/1 clients must send their request headers within HEADER_READ_TIMEOUT
        // (slowloris protection); stalled bodies are cut by the storage layer.
        let mut builder = auto::Builder::new(TokioExecutor::new());
        builder
            .http1()
            .timer(TokioTimer::new())
            .header_read_timeout(HEADER_READ_TIMEOUT);
        let conn = builder.serve_connection(io, service).into_owned();
        let conn = graceful.watch(conn);
        tokio::spawn(async move {
            if let Err(e) = conn.await {
                eprintln!("Connection error: {}", e);
            }
        });
    }

    drop(listener);
    tokio::select! {
        _ = graceful.shutdown() => {
            eprintln!("All connections closed");
        }
        _ = tokio::time::sleep(grace) => {
            eprintln!("Shutdown grace period ({}s) elapsed, dropping remaining connections", grace.as_secs());
        }
    }
}
