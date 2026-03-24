pub mod auth;
pub mod cors;
pub mod encryption;
pub mod error;
pub mod handlers;
pub mod policy;
pub mod router;
pub mod storage;
pub mod users;
pub mod xml;

use std::sync::Arc;

use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use tokio::net::TcpListener;
use tokio::sync::RwLock;

use encryption::EncryptionConfig;
use storage::Storage;
use users::UserStore;

/// Server configuration shared across all connections.
pub struct ServerConfig {
    pub storage: Arc<Storage>,
    pub user_store: Option<Arc<RwLock<UserStore>>>,
    pub admin_api_key: Option<String>,
    pub upload_ttl_secs: u64,
    pub encryption: Option<EncryptionConfig>,
}

/// Start the S3 server on the given listener with the given config.
pub async fn serve(listener: TcpListener, config: Arc<ServerConfig>) {
    loop {
        let (stream, _) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                eprintln!("Failed to accept connection: {}", e);
                continue;
            }
        };

        let config = config.clone();
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let service = service_fn(move |req| {
                let config = config.clone();
                router::route(req, config)
            });

            // Auto-negotiate HTTP/1.1 or HTTP/2 based on ALPN
            if let Err(e) = auto::Builder::new(TokioExecutor::new())
                .serve_connection(io, service)
                .await
            {
                eprintln!("Connection error: {}", e);
            }
        });
    }
}
