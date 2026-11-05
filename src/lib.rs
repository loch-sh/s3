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

/// Default cap on concurrent client connections (`S3_MAX_CONNECTIONS`).
/// Connections beyond the cap are closed right after accept.
pub const DEFAULT_MAX_CONNECTIONS: usize = 1024;

/// HTTP/2 keep-alive: ping idle connections, drop those that stop answering.
const H2_KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(30);
const H2_KEEP_ALIVE_TIMEOUT: Duration = Duration::from_secs(20);
const H2_MAX_CONCURRENT_STREAMS: u32 = 128;

fn max_connections() -> usize {
    std::env::var("S3_MAX_CONNECTIONS")
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(DEFAULT_MAX_CONNECTIONS)
}

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
    let permits = Arc::new(tokio::sync::Semaphore::new(max_connections()));

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

        // Bounded number of concurrent connections: over the cap, close now
        let Ok(permit) = permits.clone().try_acquire_owned() else {
            drop(stream);
            continue;
        };

        let config = config.clone();
        let watcher = graceful.watcher();
        tokio::spawn(async move {
            let _permit = permit;
            // A client that connects and never sends a byte is dropped
            // (hyper's header timer only starts once the protocol is known)
            // (peek waits for real data; readiness alone can be spurious)
            let mut first = [0u8; 1];
            match tokio::time::timeout(HEADER_READ_TIMEOUT, stream.peek(&mut first)).await {
                Ok(Ok(n)) if n > 0 => {}
                _ => return,
            }
            let io = TokioIo::new(stream);
            let service = service_fn(move |req| {
                let config = config.clone();
                router::route(req, config)
            });

            // Auto-negotiate HTTP/1.1 or HTTP/2 (prior knowledge / h2c).
            // HTTP/1 clients must send their request headers within HEADER_READ_TIMEOUT
            // (slowloris protection); stalled bodies are cut by the storage layer.
            let mut builder = auto::Builder::new(TokioExecutor::new());
            builder
                .http1()
                .timer(TokioTimer::new())
                .header_read_timeout(HEADER_READ_TIMEOUT);
            builder
                .http2()
                .timer(TokioTimer::new())
                .keep_alive_interval(H2_KEEP_ALIVE_INTERVAL)
                .keep_alive_timeout(H2_KEEP_ALIVE_TIMEOUT)
                .max_concurrent_streams(H2_MAX_CONCURRENT_STREAMS);
            let conn = builder.serve_connection(io, service);
            if let Err(e) = watcher.watch(conn.into_owned()).await {
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
