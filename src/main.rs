use std::net::SocketAddr;
use std::sync::Arc;

use s3::ServerConfig;
use s3::auth::Credentials;
use s3::encryption::EncryptionConfig;
use s3::storage::Storage;
use s3::users::UserStore;
use tokio::sync::RwLock;

const DEFAULT_PORT: u16 = 8080;
const DEFAULT_UPLOAD_TTL: u64 = 86400; // 24 hours
const CLEANUP_INTERVAL_SECS: u64 = 300; // 5 minutes
const DEFAULT_SHUTDOWN_GRACE_SECS: u64 = 8; // below Docker's default 10s stop timeout

struct AppConfig {
    port: u16,
    data_dir: String,
    upload_ttl_secs: u64,
    user_store: Option<Arc<RwLock<UserStore>>>,
    admin_api_key: Option<String>,
    encryption: Option<EncryptionConfig>,
    max_storage_bytes: Option<u64>,
    shutdown_grace_secs: u64,
    init_buckets: Vec<String>,
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

/// Parse an optional u64 env var. Unset or empty means `None`.
fn parse_env_opt_u64(name: &str) -> Result<Option<u64>, String> {
    match std::env::var(name) {
        Ok(raw) if raw.trim().is_empty() => Ok(None),
        Ok(raw) => raw
            .trim()
            .parse::<u64>()
            .map(Some)
            .map_err(|_| format!("{name} must be a number of bytes (u64 integer), got '{raw}'")),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(_) => Err(format!("{name} contains invalid unicode")),
    }
}

/// Parse S3_INIT_BUCKETS (comma-separated bucket names), validated like CreateBucket.
fn parse_init_buckets() -> Result<Vec<String>, String> {
    let raw = match std::env::var("S3_INIT_BUCKETS") {
        Ok(raw) => raw,
        Err(std::env::VarError::NotPresent) => return Ok(Vec::new()),
        Err(_) => return Err("S3_INIT_BUCKETS contains invalid unicode".to_string()),
    };
    let mut buckets = Vec::new();
    for name in raw.split(',').map(str::trim).filter(|n| !n.is_empty()) {
        s3::storage::validate_bucket_name(name)
            .map_err(|_| format!("S3_INIT_BUCKETS: invalid bucket name '{name}'"))?;
        if !buckets.iter().any(|b| b == name) {
            buckets.push(name.to_string());
        }
    }
    Ok(buckets)
}

fn load_user_store() -> Result<Option<Arc<RwLock<UserStore>>>, String> {
    // Priority: S3_USERS_FILE > S3_ACCESS_KEY_ID/S3_SECRET_ACCESS_KEY > None
    if let Ok(users_file) = std::env::var("S3_USERS_FILE") {
        let path = std::path::Path::new(&users_file);
        if path.exists() {
            let store = UserStore::load_from_file(path)?;
            return Ok(Some(Arc::new(RwLock::new(store))));
        }
        // Ensure parent directory exists before bootstrapping
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("Failed to create directory '{}': {}", parent.display(), e))?;
        }
        // Bootstrap: generate root user with random credentials
        let (store, access_key, _secret_key) = UserStore::bootstrap(path)?;
        eprintln!("=============================================================");
        eprintln!("  Users file not found — bootstrapping with a new root user");
        eprintln!("  File:              {}", path.display());
        eprintln!("  Access Key ID:     {}", access_key);
        eprintln!(
            "  Secret Access Key: stored in the users file (cat {})",
            path.display()
        );
        eprintln!("=============================================================");
        return Ok(Some(Arc::new(RwLock::new(store))));
    }

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
            let creds = Credentials {
                access_key_id: key_id,
                secret_access_key: secret_key,
            };
            let store = UserStore::from_single_credentials(creds);
            Ok(Some(Arc::new(RwLock::new(store))))
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
    let user_store = load_user_store()?;
    let admin_api_key = std::env::var("S3_ADMIN_API_KEY")
        .ok()
        .filter(|s| !s.is_empty());
    let encryption = load_encryption_from_env()?;
    let max_storage_bytes = parse_env_opt_u64("S3_MAX_STORAGE_BYTES")?;
    let shutdown_grace_secs = parse_env_u64("S3_SHUTDOWN_GRACE", DEFAULT_SHUTDOWN_GRACE_SECS)?;
    let init_buckets = parse_init_buckets()?;

    Ok(AppConfig {
        port,
        data_dir,
        upload_ttl_secs,
        user_store,
        admin_api_key,
        encryption,
        max_storage_bytes,
        shutdown_grace_secs,
        init_buckets,
    })
}

async fn log_startup(addr: SocketAddr, cfg: &AppConfig) {
    eprintln!("S3 server listening on http://{}", addr);
    eprintln!("Data directory: {}", cfg.data_dir);
    if let Some(ref store) = cfg.user_store {
        let store = store.read().await;
        eprintln!("Authentication: enabled ({} user(s))", store.len());
        if !store.has_file() {
            eprintln!("User management API: disabled (env-var credentials mode)");
        } else if cfg.admin_api_key.is_none() {
            eprintln!(
                "User management API: disabled (set S3_ADMIN_API_KEY to enable); users file is read-only"
            );
        } else {
            eprintln!("User management API: enabled (/_loch/users)");
        }
    } else {
        eprintln!(
            "Authentication: disabled (set S3_USERS_FILE or S3_ACCESS_KEY_ID + S3_SECRET_ACCESS_KEY to enable)"
        );
    }
    if cfg.admin_api_key.is_some() {
        eprintln!("Admin API key: configured");
    }
    if cfg.encryption.is_some() {
        eprintln!("Encryption: SSE-S3 enabled");
    } else {
        eprintln!("Encryption: SSE-S3 disabled (set S3_ENCRYPTION_KEY to enable)");
    }
    eprintln!("Upload TTL: {}s", cfg.upload_ttl_secs);
    match cfg.max_storage_bytes {
        Some(max) => eprintln!("Storage quota: {} bytes", max),
        None => eprintln!("Storage quota: unlimited (set S3_MAX_STORAGE_BYTES to enable)"),
    }
}

/// Resolve when SIGTERM (container stop) or SIGINT (Ctrl+C) is received.
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("Failed to install SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
    eprintln!("Shutting down S3 server...");
}

/// Default cap on tokio's blocking thread pool (file I/O). Tokio's own default
/// (512) can exceed container PID limits under load.
const DEFAULT_MAX_BLOCKING_THREADS: usize = 32;

fn main() {
    let max_blocking = match std::env::var("S3_MAX_BLOCKING_THREADS") {
        Ok(raw) => match raw.trim().parse::<usize>() {
            Ok(n) if n > 0 => n,
            _ => {
                eprintln!(
                    "Invalid configuration: S3_MAX_BLOCKING_THREADS must be a positive integer, got '{raw}'"
                );
                std::process::exit(1);
            }
        },
        Err(_) => DEFAULT_MAX_BLOCKING_THREADS,
    };
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .max_blocking_threads(max_blocking)
        .build()
        .expect("Failed to build the tokio runtime");
    runtime.block_on(run());
    // Do not wait for blocking tasks (e.g. a recount walk) beyond the grace period
    runtime.shutdown_timeout(std::time::Duration::from_secs(1));
}

async fn run() {
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

    let storage = Arc::new(Storage::with_quota(
        cfg.data_dir.clone().into(),
        cfg.max_storage_bytes,
    ));

    // No request is in flight yet: any *.tmp file is a leftover of an interrupted write
    let data_dir = storage.data_dir.clone();
    let (stale_count, stale_bytes) =
        tokio::task::spawn_blocking(move || s3::quota::remove_stale_tmp_files(&data_dir))
            .await
            .unwrap_or((0, 0));
    if stale_count > 0 {
        eprintln!("Removed {stale_count} stale temporary file(s) ({stale_bytes} bytes)");
    }

    // Create S3_INIT_BUCKETS (owned by the root user) when they do not exist yet
    if !cfg.init_buckets.is_empty() {
        let root_id = match cfg.user_store {
            Some(ref store) => store
                .read()
                .await
                .list_users()
                .into_iter()
                .find(|u| u.is_root)
                .map(|u| u.user_id.clone()),
            None => None,
        };
        for name in &cfg.init_buckets {
            match storage.create_bucket(name, root_id.as_deref()).await {
                Ok(()) => eprintln!("Created bucket '{name}' (S3_INIT_BUCKETS)"),
                Err(s3::error::S3Error::BucketAlreadyExists) => {}
                Err(err) => {
                    eprintln!("Failed to create bucket '{name}' from S3_INIT_BUCKETS: {err}");
                    std::process::exit(1);
                }
            }
        }
    }

    // Initial storage usage (single walk of the data directory)
    storage.quota.recount(&storage.data_dir).await;
    eprintln!("Storage usage: {} bytes", storage.quota.usage().used_bytes);
    tokio::spawn(
        storage
            .quota
            .clone()
            .run_recount_worker(storage.data_dir.clone()),
    );

    let config = Arc::new(ServerConfig {
        storage: storage.clone(),
        user_store: cfg.user_store.clone(),
        admin_api_key: cfg.admin_api_key.clone(),
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
            // Periodic reconciliation of small untracked files (metadata, ACLs, encryption tags)
            cleanup_storage
                .quota
                .recount(&cleanup_storage.data_dir)
                .await;
        }
    });

    let addr = SocketAddr::from(([0, 0, 0, 0], cfg.port));
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("Failed to bind address");

    log_startup(addr, &cfg).await;

    s3::serve_with_shutdown(
        listener,
        config,
        shutdown_signal(),
        std::time::Duration::from_secs(cfg.shutdown_grace_secs),
    )
    .await;
}
