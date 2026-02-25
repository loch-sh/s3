use std::path::PathBuf;
use std::time::SystemTime;

use hyper::body::Incoming;
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::{Storage, is_real_dir, is_regular_file};
use crate::error::S3Error;
use crate::storage::bucket::format_system_time;
use crate::storage::object::compute_file_md5;

/// Metadata for an in-progress multipart upload.
#[derive(serde::Serialize, serde::Deserialize)]
pub(crate) struct UploadMeta {
    pub key: String,
    pub initiated: String,
    /// SSE algorithm for this upload ("AES256" for SSE-S3, "SSE-C" for SSE-C).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sse_algorithm: Option<String>,
    /// Base64 MD5 of the customer key (SSE-C only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sse_customer_key_md5: Option<String>,
}

/// Info about a single uploaded part.
pub struct PartInfo {
    pub part_number: u32,
    pub etag: String,
    pub size: u64,
    pub last_modified: SystemTime,
}

/// Info about an in-progress upload (for listing).
pub struct UploadInfo {
    pub key: String,
    pub upload_id: String,
    pub initiated: String,
}

const UPLOADS_DIR: &str = ".uploads";
const META_FILE: &str = ".meta.json";

impl Storage {
    /// Path to the .uploads directory within a bucket.
    fn uploads_dir(&self, bucket: &str) -> PathBuf {
        self.data_dir.join(bucket).join(UPLOADS_DIR)
    }

    /// Path to a specific upload directory.
    fn upload_path(&self, bucket: &str, upload_id: &str) -> PathBuf {
        self.uploads_dir(bucket).join(upload_id)
    }

    /// Path to a specific part file.
    fn part_path(&self, bucket: &str, upload_id: &str, part_number: u32) -> PathBuf {
        self.upload_path(bucket, upload_id)
            .join(part_number.to_string())
    }

    /// Create a new multipart upload. Returns the upload ID.
    pub async fn create_multipart_upload(
        &self,
        bucket: &str,
        key: &str,
        sse_algorithm: Option<String>,
        sse_customer_key_md5: Option<String>,
    ) -> Result<String, S3Error> {
        self.head_bucket(bucket).await?;
        // Validate key via object_path (also checks path traversal)
        let _ = self.object_path(bucket, key)?;

        let upload_id = uuid::Uuid::new_v4().to_string();
        let upload_dir = self.upload_path(bucket, &upload_id);
        fs::create_dir_all(&upload_dir)
            .await
            .map_err(|e| S3Error::InternalError(e.to_string()))?;

        let meta = UploadMeta {
            key: key.to_string(),
            initiated: format_system_time(SystemTime::now()),
            sse_algorithm,
            sse_customer_key_md5,
        };
        let meta_json =
            serde_json::to_vec(&meta).map_err(|e| S3Error::InternalError(e.to_string()))?;
        fs::write(upload_dir.join(META_FILE), &meta_json)
            .await
            .map_err(|e| S3Error::InternalError(e.to_string()))?;

        Ok(upload_id)
    }

    /// Read upload metadata for a multipart upload.
    pub(crate) async fn get_upload_meta(
        &self,
        bucket: &str,
        upload_id: &str,
    ) -> Result<UploadMeta, S3Error> {
        let upload_dir = self.upload_path(bucket, upload_id);
        let meta_path = upload_dir.join(META_FILE);
        if !is_regular_file(&meta_path).await {
            return Err(S3Error::NoSuchUpload);
        }
        let data = fs::read(&meta_path)
            .await
            .map_err(|e| S3Error::InternalError(e.to_string()))?;
        serde_json::from_slice(&data).map_err(|e| S3Error::InternalError(e.to_string()))
    }

    /// Upload a part by streaming request body to disk. Returns the ETag.
    pub async fn upload_part(
        &self,
        bucket: &str,
        upload_id: &str,
        part_number: u32,
        body: Incoming,
        aws_chunked: bool,
    ) -> Result<String, S3Error> {
        self.head_bucket(bucket).await?;

        let upload_dir = self.upload_path(bucket, upload_id);
        if !is_real_dir(&upload_dir).await {
            return Err(S3Error::NoSuchUpload);
        }

        let part_path = self.part_path(bucket, upload_id, part_number);
        // UUID-based temp file to prevent TOCTOU race conditions
        let tmp_name = format!("{}.{}.tmp", part_number, uuid::Uuid::new_v4());
        let tmp_path = upload_dir.join(&tmp_name);
        let mut file = tokio::fs::File::create(&tmp_path)
            .await
            .map_err(|e| S3Error::InternalError(e.to_string()))?;

        let etag =
            crate::storage::object::stream_body_to_file(&mut file, body, aws_chunked).await?;
        drop(file);

        fs::rename(&tmp_path, &part_path)
            .await
            .map_err(|e| S3Error::InternalError(e.to_string()))?;

        Ok(etag)
    }

    /// Complete a multipart upload: assemble parts into the final object.
    /// `parts` is a list of (part_number, expected_etag).
    pub async fn complete_multipart_upload(
        &self,
        bucket: &str,
        upload_id: &str,
        parts: Vec<(u32, String)>,
    ) -> Result<(String, String), S3Error> {
        self.head_bucket(bucket).await?;

        let upload_dir = self.upload_path(bucket, upload_id);
        if !is_real_dir(&upload_dir).await {
            return Err(S3Error::NoSuchUpload);
        }

        // Read upload metadata to get the key
        let meta_path = upload_dir.join(META_FILE);
        let meta_bytes = fs::read(&meta_path)
            .await
            .map_err(|e| S3Error::InternalError(e.to_string()))?;
        let meta: UploadMeta = serde_json::from_slice(&meta_bytes)
            .map_err(|e| S3Error::InternalError(e.to_string()))?;

        // Validate part ordering
        for i in 1..parts.len() {
            if parts[i].0 <= parts[i - 1].0 {
                return Err(S3Error::InvalidPartOrder);
            }
        }

        // Prepare destination path
        let object_path = self.object_path(bucket, &meta.key)?;
        if let Some(parent) = object_path.parent() {
            fs::create_dir_all(parent)
                .await
                .map_err(|e| S3Error::InternalError(e.to_string()))?;
        }

        // UUID-based temp file for atomic assembly
        let tmp_name = format!(
            "{}.{}.tmp",
            object_path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy(),
            uuid::Uuid::new_v4()
        );
        let tmp_path = object_path.with_file_name(&tmp_name);
        let mut dst_file = tokio::fs::File::create(&tmp_path)
            .await
            .map_err(|e| S3Error::InternalError(e.to_string()))?;

        // Compute composite ETag: MD5 of concatenated binary part MD5 digests
        let mut md5_of_md5s = md5::Context::new();
        let part_count = parts.len();

        for (part_number, expected_etag) in &parts {
            let part_path = self.part_path(bucket, upload_id, *part_number);
            if !is_regular_file(&part_path).await {
                let _ = fs::remove_file(&tmp_path).await;
                return Err(S3Error::InvalidPart);
            }

            // Stream part to destination while computing its MD5
            let mut part_file = tokio::fs::File::open(&part_path)
                .await
                .map_err(|e| S3Error::InternalError(e.to_string()))?;

            let mut part_md5 = md5::Context::new();
            let mut buf = [0u8; 8192];
            loop {
                let n = part_file
                    .read(&mut buf)
                    .await
                    .map_err(|e| S3Error::InternalError(e.to_string()))?;
                if n == 0 {
                    break;
                }
                part_md5.consume(&buf[..n]);
                dst_file
                    .write_all(&buf[..n])
                    .await
                    .map_err(|e| S3Error::InternalError(e.to_string()))?;
            }

            let part_digest = part_md5.finalize();
            let part_etag = format!("\"{:x}\"", part_digest);

            // Verify ETag matches
            let expected = expected_etag.trim_matches('"');
            let actual = part_etag.trim_matches('"');
            if expected != actual {
                let _ = fs::remove_file(&tmp_path).await;
                return Err(S3Error::InvalidPart);
            }

            md5_of_md5s.consume(&*part_digest);
        }

        dst_file
            .flush()
            .await
            .map_err(|e| S3Error::InternalError(e.to_string()))?;
        drop(dst_file);

        // Atomic rename
        fs::rename(&tmp_path, &object_path)
            .await
            .map_err(|e| S3Error::InternalError(e.to_string()))?;

        // S3-style multipart ETag: md5_of_concatenated_part_md5s-part_count
        let composite_etag = format!("\"{:x}-{}\"", md5_of_md5s.finalize(), part_count);

        // Clean up upload directory
        let _ = fs::remove_dir_all(&upload_dir).await;

        Ok((meta.key, composite_etag))
    }

    /// Abort a multipart upload (delete all parts and metadata).
    pub async fn abort_multipart_upload(
        &self,
        bucket: &str,
        upload_id: &str,
    ) -> Result<(), S3Error> {
        self.head_bucket(bucket).await?;

        let upload_dir = self.upload_path(bucket, upload_id);
        if !is_real_dir(&upload_dir).await {
            return Err(S3Error::NoSuchUpload);
        }

        fs::remove_dir_all(&upload_dir)
            .await
            .map_err(|e| S3Error::InternalError(e.to_string()))?;

        Ok(())
    }

    /// List the parts uploaded for a multipart upload.
    pub async fn list_parts(
        &self,
        bucket: &str,
        upload_id: &str,
    ) -> Result<(String, Vec<PartInfo>), S3Error> {
        self.head_bucket(bucket).await?;

        let upload_dir = self.upload_path(bucket, upload_id);
        if !is_real_dir(&upload_dir).await {
            return Err(S3Error::NoSuchUpload);
        }

        // Read the key from metadata
        let meta_path = upload_dir.join(META_FILE);
        let meta_bytes = fs::read(&meta_path)
            .await
            .map_err(|e| S3Error::InternalError(e.to_string()))?;
        let meta: UploadMeta = serde_json::from_slice(&meta_bytes)
            .map_err(|e| S3Error::InternalError(e.to_string()))?;

        let mut parts = Vec::new();
        let mut entries = fs::read_dir(&upload_dir)
            .await
            .map_err(|e| S3Error::InternalError(e.to_string()))?;

        while let Some(entry) = entries
            .next_entry()
            .await
            .map_err(|e| S3Error::InternalError(e.to_string()))?
        {
            let name = entry.file_name().to_string_lossy().to_string();
            if name == META_FILE || name.ends_with("tmp") {
                continue;
            }
            if let Ok(part_number) = name.parse::<u32>() {
                let file_meta = match fs::symlink_metadata(entry.path()).await {
                    Ok(m) if m.is_file() && !m.file_type().is_symlink() => m,
                    _ => continue,
                };
                let part_path = entry.path();
                let etag = compute_file_md5(&part_path).await?;
                parts.push(PartInfo {
                    part_number,
                    etag,
                    size: file_meta.len(),
                    last_modified: file_meta.modified().unwrap_or(SystemTime::UNIX_EPOCH),
                });
            }
        }

        parts.sort_by_key(|p| p.part_number);
        Ok((meta.key, parts))
    }

    /// List all in-progress multipart uploads for a bucket.
    pub async fn list_multipart_uploads(&self, bucket: &str) -> Result<Vec<UploadInfo>, S3Error> {
        self.head_bucket(bucket).await?;

        let uploads_dir = self.uploads_dir(bucket);
        if !is_real_dir(&uploads_dir).await {
            return Ok(Vec::new());
        }

        let mut uploads = Vec::new();
        let mut entries = fs::read_dir(&uploads_dir)
            .await
            .map_err(|e| S3Error::InternalError(e.to_string()))?;

        while let Some(entry) = entries
            .next_entry()
            .await
            .map_err(|e| S3Error::InternalError(e.to_string()))?
        {
            let meta = match fs::symlink_metadata(entry.path()).await {
                Ok(m) if m.is_dir() && !m.file_type().is_symlink() => m,
                _ => continue,
            };
            let _ = meta; // used above for the check
            let upload_id = entry.file_name().to_string_lossy().to_string();
            let meta_path = entry.path().join(META_FILE);
            if let Ok(meta_bytes) = fs::read(&meta_path).await {
                if let Ok(upload_meta) = serde_json::from_slice::<UploadMeta>(&meta_bytes) {
                    uploads.push(UploadInfo {
                        key: upload_meta.key,
                        upload_id,
                        initiated: upload_meta.initiated,
                    });
                }
            }
        }

        uploads.sort_by(|a, b| a.key.cmp(&b.key).then(a.upload_id.cmp(&b.upload_id)));
        Ok(uploads)
    }

    /// Delete expired multipart uploads older than `ttl_secs`.
    pub async fn cleanup_expired_uploads(&self, ttl_secs: u64) {
        let now = chrono::Utc::now();

        let mut buckets = match fs::read_dir(&self.data_dir).await {
            Ok(entries) => entries,
            Err(_) => return,
        };

        while let Ok(Some(bucket_entry)) = buckets.next_entry().await {
            let bucket_meta = match fs::symlink_metadata(bucket_entry.path()).await {
                Ok(m) if m.is_dir() && !m.file_type().is_symlink() => m,
                _ => continue,
            };
            let _ = bucket_meta;

            let uploads_dir = bucket_entry.path().join(UPLOADS_DIR);
            if !is_real_dir(&uploads_dir).await {
                continue;
            }

            let mut uploads = match fs::read_dir(&uploads_dir).await {
                Ok(entries) => entries,
                Err(_) => continue,
            };

            while let Ok(Some(upload_entry)) = uploads.next_entry().await {
                let meta_path = upload_entry.path().join(META_FILE);
                let meta_bytes = match fs::read(&meta_path).await {
                    Ok(b) => b,
                    Err(_) => continue,
                };
                let meta: UploadMeta = match serde_json::from_slice(&meta_bytes) {
                    Ok(m) => m,
                    Err(_) => continue,
                };

                if let Ok(initiated) = chrono::DateTime::parse_from_rfc3339(&meta.initiated) {
                    let age = now.signed_duration_since(initiated);
                    if age.num_seconds() > ttl_secs as i64 {
                        let _ = fs::remove_dir_all(upload_entry.path()).await;
                    }
                } else if let Ok(initiated) =
                    chrono::NaiveDateTime::parse_from_str(&meta.initiated, "%Y-%m-%dT%H:%M:%S%.3fZ")
                {
                    let initiated_utc = initiated.and_utc();
                    let age = now.signed_duration_since(initiated_utc);
                    if age.num_seconds() > ttl_secs as i64 {
                        let _ = fs::remove_dir_all(upload_entry.path()).await;
                    }
                }
            }
        }
    }
}
