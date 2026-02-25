use std::net::SocketAddr;
use std::sync::Arc;

use s3::ServerConfig;
use s3::auth::Credentials;
use s3::encryption::EncryptionConfig;
use s3::storage::Storage;

const DEFAULT_PORT: u16 = 8080;
const DEFAULT_UPLOAD_TTL: u64 = 86400; // 24 hours
const CLEANUP_INTERVAL_SECS: u64 = 300; // 5 minutes

struct AppConfig {
    port: u16,
    data_dir: String,
    upload_ttl_secs: u64,
    credentials: Option<Credentials>,
    encryption: Option<EncryptionConfig>,
}

fn parse_env_u16(name: &str, default: u16) -> Result<u16, String> {
    match std::env::var(name) {
        Ok(raw) => raw
            .parse::<u16>()
            .map_err(|_| format!("{name} must be a valid u16 integer, got '{raw}'")),
        Err(std::env::VarError::NotPresent) => Ok(default),
        Err(_) => Err(format!("{name} contains invalid unicode")),
    }
}

fn parse_env_u64(name: &str, default: u64) -> Result<u64, String> {
    match std::env::var(name) {
        Ok(raw) => raw
            .parse::<u64>()
            .map_err(|_| format!("{name} must be a valid u64 integer, got '{raw}'")),
        Err(std::env::VarError::NotPresent) => Ok(default),
        Err(_) => Err(format!("{name} contains invalid unicode")),
    }
}

fn load_credentials_from_env() -> Result<Option<Credentials>, String> {
    let key_id = std::env::var("S3_ACCESS_KEY_ID").ok();
    let secret_key = std::env::var("S3_SECRET_ACCESS_KEY").ok();
    match (key_id, secret_key) {
        (None, None) => Ok(None),
        (Some(key_id), Some(secret_key)) => {
            if key_id.is_empty() || secret_key.is_empty() {
                return Err(
                    "S3_ACCESS_KEY_ID and S3_SECRET_ACCESS_KEY must be non-empty when set"
                        .to_string(),
                );
            }
            Ok(Some(Credentials {
                access_key_id: key_id,
                secret_access_key: secret_key,
            }))
        }
        _ => Err("S3_ACCESS_KEY_ID and S3_SECRET_ACCESS_KEY must be set together".to_string()),
    }
}

fn load_encryption_from_env() -> Result<Option<EncryptionConfig>, String> {
    let b64_key = match std::env::var("S3_ENCRYPTION_KEY") {
        Ok(val) => val,
        Err(std::env::VarError::NotPresent) => return Ok(None),
        Err(_) => return Err("S3_ENCRYPTION_KEY contains invalid unicode".to_string()),
    };

    use base64::Engine;
    let key_bytes = base64::engine::general_purpose::STANDARD
        .decode(&b64_key)
        .map_err(|_| "S3_ENCRYPTION_KEY must be valid base64".to_string())?;
    if key_bytes.len() != 32 {
        return Err("S3_ENCRYPTION_KEY must be exactly 32 bytes (256 bits)".to_string());
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(&key_bytes);
    Ok(Some(EncryptionConfig { master_key: key }))
}

fn load_app_config() -> Result<AppConfig, String> {
    let port = parse_env_u16("S3_PORT", DEFAULT_PORT)?;
    let data_dir = std::env::var("S3_DATA_DIR").unwrap_or_else(|_| "./data".to_string());
    let upload_ttl_secs = parse_env_u64("S3_UPLOAD_TTL", DEFAULT_UPLOAD_TTL)?;
    let credentials = load_credentials_from_env()?;
    let encryption = load_encryption_from_env()?;

    Ok(AppConfig {
        port,
        data_dir,
        upload_ttl_secs,
        credentials,
        encryption,
    })
}

fn log_startup(addr: SocketAddr, cfg: &AppConfig) {
    eprintln!("S3 server listening on http://{}", addr);
    eprintln!("Data directory: {}", cfg.data_dir);
    if cfg.credentials.is_some() {
        eprintln!("Authentication: enabled");
    } else {
        eprintln!(
            "Authentication: disabled (set S3_ACCESS_KEY_ID and S3_SECRET_ACCESS_KEY to enable)"
        );
    }
    if cfg.encryption.is_some() {
        eprintln!("Encryption: SSE-S3 enabled");
    } else {
        eprintln!("Encryption: SSE-S3 disabled (set S3_ENCRYPTION_KEY to enable)");
    }
    eprintln!("Upload TTL: {}s", cfg.upload_ttl_secs);
}

#[tokio::main]
async fn main() {
    let cfg = match load_app_config() {
        Ok(cfg) => cfg,
        Err(err) => {
            eprintln!("Invalid configuration: {err}");
            std::process::exit(1);
        }
    };

    // Ensure data directory exists
    if let Err(err) = tokio::fs::create_dir_all(&cfg.data_dir).await {
        eprintln!("Failed to create data directory '{}': {err}", cfg.data_dir);
        std::process::exit(1);
    }

    let storage = Arc::new(Storage::new(cfg.data_dir.clone().into()));

    let config = Arc::new(ServerConfig {
        storage: storage.clone(),
        credentials: cfg.credentials.clone(),
        upload_ttl_secs: cfg.upload_ttl_secs,
        encryption: cfg.encryption.clone(),
    });

    // Spawn background task to clean up expired multipart uploads
    let cleanup_storage = storage.clone();
    let upload_ttl_secs = cfg.upload_ttl_secs;
    tokio::spawn(async move {
        let mut ticker =
            tokio::time::interval(std::time::Duration::from_secs(CLEANUP_INTERVAL_SECS));
        loop {
            ticker.tick().await;
            cleanup_storage
                .cleanup_expired_uploads(upload_ttl_secs)
                .await;
        }
    });

    let addr = SocketAddr::from(([0, 0, 0, 0], cfg.port));
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("Failed to bind address");

    log_startup(addr, &cfg);

    tokio::select! {
        _ = s3::serve(listener, config) => {}
        _ = tokio::signal::ctrl_c() => {
            eprintln!("\nShutting down S3 server...");
        }
    }
}
