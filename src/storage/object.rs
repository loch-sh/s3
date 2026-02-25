use std::collections::{BTreeSet, HashMap};
use std::path::PathBuf;
use std::time::SystemTime;

use http_body_util::BodyExt;
use hyper::body::Incoming;
use serde::{Deserialize, Serialize};
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::{INTERNAL_NAMES, Storage, atomic_tmp_path, guess_content_type, is_regular_file};
use crate::encryption::EncryptionMeta;
use crate::error::S3Error;

const META_DIR: &str = ".meta";

/// Persisted object metadata (system headers + user-defined x-amz-meta-*).
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct StoredMetadata {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_control: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_disposition: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_encoding: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_language: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires: Option<String>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub user_metadata: HashMap<String, String>,
    /// Encryption parameters, if object is encrypted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encryption: Option<EncryptionMeta>,
    /// Plaintext ETag (stored for encrypted objects since it cannot be recomputed from ciphertext).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub etag: Option<String>,
}

/// Object metadata returned by head_object and get_object_meta.
pub struct ObjectMetadata {
    pub content_length: u64,
    pub last_modified: SystemTime,
    pub etag: String,
    pub content_type: String,
    pub cache_control: Option<String>,
    pub content_disposition: Option<String>,
    pub content_encoding: Option<String>,
    pub content_language: Option<String>,
    pub expires: Option<String>,
    pub user_metadata: HashMap<String, String>,
    /// Encryption parameters (if encrypted).
    pub encryption: Option<EncryptionMeta>,
}

/// Result of a list_objects operation.
pub struct ListObjectsResult {
    pub name: String,
    pub prefix: String,
    pub delimiter: Option<String>,
    pub max_keys: usize,
    pub is_truncated: bool,
    pub next_continuation_token: Option<String>,
    pub objects: Vec<ObjectInfo>,
    pub common_prefixes: Vec<String>,
}

/// Info about a single object in a listing.
pub struct ObjectInfo {
    pub key: String,
    pub last_modified: SystemTime,
    pub size: u64,
    pub etag: String,
}

impl Storage {
    /// Write an object to disk by streaming the request body.
    /// Uses atomic write (UUID-based temp file + rename) and incremental MD5.
    /// Returns the ETag (MD5 hex digest).
    pub async fn put_object(
        &self,
        bucket: &str,
        key: &str,
        body: Incoming,
        aws_chunked: bool,
    ) -> Result<String, S3Error> {
        self.head_bucket(bucket).await?;

        let object_path = self.object_path(bucket, key)?;
        if let Some(parent) = object_path.parent() {
            fs::create_dir_all(parent)
                .await
                .map_err(|e| S3Error::InternalError(e.to_string()))?;
        }

        // UUID-based temp file to prevent TOCTOU race conditions
        let tmp_path = atomic_tmp_path(&object_path);
        let mut file = tokio::fs::File::create(&tmp_path)
            .await
            .map_err(|e| S3Error::InternalError(e.to_string()))?;

        let etag = stream_body_to_file(&mut file, body, aws_chunked).await?;
        drop(file);

        fs::rename(&tmp_path, &object_path)
            .await
            .map_err(|e| S3Error::InternalError(e.to_string()))?;

        Ok(etag)
    }

    /// Get object metadata and file path for streaming by the handler.
    /// Does NOT load the file content into memory.
    pub async fn get_object_meta(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<(ObjectMetadata, PathBuf), S3Error> {
        self.head_bucket(bucket).await?;

        let object_path = self.object_path(bucket, key)?;
        if !is_regular_file(&object_path).await {
            return Err(S3Error::NoSuchKey);
        }

        let meta = fs::symlink_metadata(&object_path)
            .await
            .map_err(|e| S3Error::InternalError(e.to_string()))?;

        let last_modified = meta.modified().unwrap_or(SystemTime::UNIX_EPOCH);
        let stored = self.get_stored_metadata(bucket, key).await?;

        // Use stored ETag for encrypted objects, compute from file otherwise
        let etag = if let Some(ref stored_etag) = stored.etag {
            stored_etag.clone()
        } else {
            compute_file_md5(&object_path).await?
        };

        // Use plaintext size for encrypted objects, file size otherwise
        let content_length = if let Some(ref enc) = stored.encryption {
            enc.plaintext_size
        } else {
            meta.len()
        };

        let content_type = stored
            .content_type
            .clone()
            .unwrap_or_else(|| guess_content_type(key));

        Ok((
            ObjectMetadata {
                content_length,
                last_modified,
                etag,
                content_type,
                cache_control: stored.cache_control,
                content_disposition: stored.content_disposition,
                content_encoding: stored.content_encoding,
                content_language: stored.content_language,
                expires: stored.expires,
                user_metadata: stored.user_metadata,
                encryption: stored.encryption,
            },
            object_path,
        ))
    }

    /// Get object metadata without reading the full content into memory.
    pub async fn head_object(&self, bucket: &str, key: &str) -> Result<ObjectMetadata, S3Error> {
        let (meta, _path) = self.get_object_meta(bucket, key).await?;
        Ok(meta)
    }

    /// Delete an object. Returns Ok even if the object does not exist (S3 behavior).
    pub async fn delete_object(&self, bucket: &str, key: &str) -> Result<(), S3Error> {
        self.head_bucket(bucket).await?;

        let object_path = self.object_path(bucket, key)?;
        if is_regular_file(&object_path).await {
            fs::remove_file(&object_path)
                .await
                .map_err(|e| S3Error::InternalError(e.to_string()))?;

            // Clean up empty parent directories (but not the bucket root)
            let bucket_root = self.data_dir.join(bucket);
            let mut current = object_path.parent().map(|p| p.to_path_buf());
            while let Some(dir) = current {
                if dir == bucket_root {
                    break;
                }
                // Try to remove; if it fails (not empty), stop
                if fs::remove_dir(&dir).await.is_err() {
                    break;
                }
                current = dir.parent().map(|p| p.to_path_buf());
            }
        }

        // Also remove the metadata sidecar and ACL
        self.delete_object_metadata(bucket, key).await?;
        self.delete_object_acl(bucket, key).await?;

        Ok(())
    }

    /// Copy an object within the storage (streams file-to-file, no full buffering).
    pub async fn copy_object(
        &self,
        src_bucket: &str,
        src_key: &str,
        dst_bucket: &str,
        dst_key: &str,
    ) -> Result<ObjectMetadata, S3Error> {
        self.head_bucket(src_bucket).await?;
        self.head_bucket(dst_bucket).await?;

        let src_path = self.object_path(src_bucket, src_key)?;
        if !is_regular_file(&src_path).await {
            return Err(S3Error::NoSuchKey);
        }

        let dst_path = self.object_path(dst_bucket, dst_key)?;
        if let Some(parent) = dst_path.parent() {
            fs::create_dir_all(parent)
                .await
                .map_err(|e| S3Error::InternalError(e.to_string()))?;
        }

        // UUID-based temp file for atomic copy
        let tmp_path = atomic_tmp_path(&dst_path);
        fs::copy(&src_path, &tmp_path)
            .await
            .map_err(|e| S3Error::InternalError(e.to_string()))?;
        fs::rename(&tmp_path, &dst_path)
            .await
            .map_err(|e| S3Error::InternalError(e.to_string()))?;

        let etag = compute_file_md5(&dst_path).await?;

        let meta = fs::symlink_metadata(&dst_path)
            .await
            .map_err(|e| S3Error::InternalError(e.to_string()))?;

        let last_modified = meta.modified().unwrap_or(SystemTime::UNIX_EPOCH);

        // Copy metadata sidecar from source to destination
        let stored = self.get_stored_metadata(src_bucket, src_key).await?;
        self.put_object_metadata(dst_bucket, dst_key, &stored)
            .await?;

        let content_type = stored
            .content_type
            .clone()
            .unwrap_or_else(|| guess_content_type(dst_key));

        Ok(ObjectMetadata {
            content_length: meta.len(),
            last_modified,
            etag,
            content_type,
            cache_control: stored.cache_control,
            content_disposition: stored.content_disposition,
            content_encoding: stored.content_encoding,
            content_language: stored.content_language,
            expires: stored.expires,
            user_metadata: stored.user_metadata,
            encryption: stored.encryption,
        })
    }

    // -- Object metadata persistence --

    /// Path to an object's metadata sidecar: {bucket}/.meta/{key}.json
    fn object_meta_path(&self, bucket: &str, key: &str) -> Result<PathBuf, S3Error> {
        let bucket_dir = self.data_dir.join(bucket);
        Ok(bucket_dir.join(META_DIR).join(format!("{}.json", key)))
    }

    /// Write object metadata to disk (atomic: write tmp then rename).
    pub async fn put_object_metadata(
        &self,
        bucket: &str,
        key: &str,
        metadata: &StoredMetadata,
    ) -> Result<(), S3Error> {
        let meta_path = self.object_meta_path(bucket, key)?;
        if let Some(parent) = meta_path.parent() {
            fs::create_dir_all(parent)
                .await
                .map_err(|e| S3Error::InternalError(e.to_string()))?;
        }
        let json =
            serde_json::to_vec(metadata).map_err(|e| S3Error::InternalError(e.to_string()))?;
        let tmp_path = meta_path.with_extension("json.tmp");
        fs::write(&tmp_path, &json)
            .await
            .map_err(|e| S3Error::InternalError(e.to_string()))?;
        fs::rename(&tmp_path, &meta_path)
            .await
            .map_err(|e| S3Error::InternalError(e.to_string()))?;
        Ok(())
    }

    /// Read object metadata from disk. Returns Default if no metadata file exists.
    pub async fn get_stored_metadata(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<StoredMetadata, S3Error> {
        let meta_path = self.object_meta_path(bucket, key)?;
        if !is_regular_file(&meta_path).await {
            return Ok(StoredMetadata::default());
        }
        let data = fs::read(&meta_path)
            .await
            .map_err(|e| S3Error::InternalError(e.to_string()))?;
        serde_json::from_slice(&data).map_err(|e| S3Error::InternalError(e.to_string()))
    }

    /// Delete object metadata file and clean up empty parent directories.
    pub async fn delete_object_metadata(&self, bucket: &str, key: &str) -> Result<(), S3Error> {
        let meta_path = self.object_meta_path(bucket, key)?;
        if is_regular_file(&meta_path).await {
            let _ = fs::remove_file(&meta_path).await;
            // Clean up empty parent directories up to .meta/
            let meta_root = self.data_dir.join(bucket).join(META_DIR);
            let mut current = meta_path.parent().map(|p| p.to_path_buf());
            while let Some(dir) = current {
                if dir == meta_root {
                    let _ = fs::remove_dir(&dir).await;
                    break;
                }
                if fs::remove_dir(&dir).await.is_err() {
                    break;
                }
                current = dir.parent().map(|p| p.to_path_buf());
            }
        }
        Ok(())
    }

    /// List objects in a bucket with optional prefix, delimiter, and pagination.
    pub async fn list_objects(
        &self,
        bucket: &str,
        prefix: &str,
        delimiter: &str,
        max_keys: usize,
        start_after: &str,
    ) -> Result<ListObjectsResult, S3Error> {
        self.head_bucket(bucket).await?;

        let bucket_path = self.data_dir.join(bucket);

        // Collect all object keys recursively
        let mut all_keys = Vec::new();
        collect_keys(&bucket_path, &bucket_path, &mut all_keys).await?;
        all_keys.sort();

        let delimiter_opt = if delimiter.is_empty() {
            None
        } else {
            Some(delimiter.to_string())
        };

        // Filter by prefix and start_after
        let filtered: Vec<String> = all_keys
            .into_iter()
            .filter(|k| k.starts_with(prefix))
            .filter(|k| start_after.is_empty() || k.as_str() > start_after)
            .collect();

        let mut objects = Vec::new();
        let mut common_prefixes = BTreeSet::new();

        for key in &filtered {
            if !delimiter.is_empty() {
                // Check if key has delimiter after prefix
                let after_prefix = &key[prefix.len()..];
                if let Some(pos) = after_prefix.find(delimiter) {
                    let cp = format!("{}{}", prefix, &after_prefix[..=pos]);
                    common_prefixes.insert(cp);
                    continue;
                }
            }
            objects.push(key.clone());
        }

        let total_count = objects.len() + common_prefixes.len();
        let is_truncated = total_count > max_keys;

        // Truncate to max_keys
        let mut result_objects = Vec::new();
        let mut count = 0;

        for key in &objects {
            if count >= max_keys {
                break;
            }
            // Keys come from the filesystem (collect_keys), skip on validation error
            let object_path = match self.object_path(bucket, key) {
                Ok(p) => p,
                Err(_) => continue,
            };
            if let Ok(meta) = fs::symlink_metadata(&object_path).await {
                if meta.is_file() && !meta.file_type().is_symlink() {
                    let etag = compute_file_md5(&object_path).await.unwrap_or_default();
                    result_objects.push(ObjectInfo {
                        key: key.clone(),
                        last_modified: meta.modified().unwrap_or(SystemTime::UNIX_EPOCH),
                        size: meta.len(),
                        etag,
                    });
                    count += 1;
                }
            }
        }

        let result_prefixes: Vec<String> = common_prefixes.into_iter().collect();

        let next_token = if is_truncated {
            result_objects.last().map(|o| o.key.clone())
        } else {
            None
        };

        Ok(ListObjectsResult {
            name: bucket.to_string(),
            prefix: prefix.to_string(),
            delimiter: delimiter_opt,
            max_keys,
            is_truncated,
            next_continuation_token: next_token,
            objects: result_objects,
            common_prefixes: result_prefixes,
        })
    }
}

/// Recursively collect all object keys relative to the bucket root.
/// Uses symlink_metadata to avoid following symlinks.
async fn collect_keys(
    base: &std::path::Path,
    current: &std::path::Path,
    keys: &mut Vec<String>,
) -> Result<(), S3Error> {
    let mut entries = fs::read_dir(current)
        .await
        .map_err(|e| S3Error::InternalError(e.to_string()))?;

    while let Some(entry) = entries
        .next_entry()
        .await
        .map_err(|e| S3Error::InternalError(e.to_string()))?
    {
        let name = entry.file_name().to_string_lossy().to_string();

        // Directory marker sentinel — emit the directory key (e.g. "prefix/")
        if name == super::DIR_MARKER {
            let path = entry.path();
            if let Ok(m) = fs::symlink_metadata(&path).await {
                if m.is_file() && !m.file_type().is_symlink() {
                    if let Ok(relative) = current.strip_prefix(base) {
                        if !relative.as_os_str().is_empty() {
                            keys.push(format!("{}/", relative.to_string_lossy()));
                        }
                    }
                }
            }
            continue;
        }

        // Skip internal files and directories
        if INTERNAL_NAMES.contains(&name.as_str()) || name.ends_with(".tmp") {
            continue;
        }

        let path = entry.path();
        // Use symlink_metadata to not follow symlinks
        let meta = match fs::symlink_metadata(&path).await {
            Ok(m) => m,
            Err(_) => continue,
        };

        // Skip symlinks entirely
        if meta.file_type().is_symlink() {
            continue;
        }

        if meta.is_dir() {
            Box::pin(collect_keys(base, &path, keys)).await?;
        } else if meta.is_file() {
            if let Ok(relative) = path.strip_prefix(base) {
                keys.push(relative.to_string_lossy().to_string());
            }
        }
    }

    Ok(())
}

/// Stream an HTTP body to a file, computing MD5 incrementally.
/// If `aws_chunked` is true, the body is first collected and decoded from
/// the AWS chunked transfer encoding before writing.
/// Returns the MD5 ETag (quoted hex digest).
pub(crate) async fn stream_body_to_file(
    file: &mut tokio::fs::File,
    mut body: Incoming,
    aws_chunked: bool,
) -> Result<String, S3Error> {
    let mut md5_ctx = md5::Context::new();

    if aws_chunked {
        let mut raw = Vec::new();
        while let Some(frame) = body.frame().await {
            let frame = frame.map_err(|e| S3Error::InternalError(e.to_string()))?;
            if let Ok(data) = frame.into_data() {
                raw.extend_from_slice(&data);
            }
        }
        let decoded = decode_aws_chunked(&raw);
        md5_ctx.consume(&decoded);
        file.write_all(&decoded)
            .await
            .map_err(|e| S3Error::InternalError(e.to_string()))?;
    } else {
        while let Some(frame) = body.frame().await {
            let frame = frame.map_err(|e| S3Error::InternalError(e.to_string()))?;
            if let Ok(data) = frame.into_data() {
                md5_ctx.consume(&data);
                file.write_all(&data)
                    .await
                    .map_err(|e| S3Error::InternalError(e.to_string()))?;
            }
        }
    }

    file.flush()
        .await
        .map_err(|e| S3Error::InternalError(e.to_string()))?;

    Ok(format!("\"{:x}\"", md5_ctx.finalize()))
}

/// Decode an AWS chunked transfer encoded body.
/// Format: <hex-size>[;chunk-extension...]\r\n<data>\r\n ... 0[;...]\r\n[trailers]\r\n
fn decode_aws_chunked(data: &[u8]) -> Vec<u8> {
    let mut result = Vec::new();
    let mut pos = 0;

    loop {
        if pos >= data.len() {
            break;
        }

        // Find end of chunk-size line
        let line_end = match find_crlf(data, pos) {
            Some(i) => i,
            None => break,
        };

        // Parse chunk size (ignore extensions after ';')
        let line = &data[pos..line_end];
        let size_part = match line.iter().position(|&b| b == b';') {
            Some(i) => &line[..i],
            None => line,
        };
        let size_str = std::str::from_utf8(size_part).unwrap_or("0").trim();
        let chunk_size = usize::from_str_radix(size_str, 16).unwrap_or(0);

        pos = line_end + 2; // skip \r\n

        if chunk_size == 0 {
            break; // final chunk, ignore trailers
        }

        // Read chunk data
        let end = (pos + chunk_size).min(data.len());
        result.extend_from_slice(&data[pos..end]);
        pos = end + 2; // skip data + \r\n
    }

    result
}

/// Find the position of the next \r\n in data starting from `start`.
fn find_crlf(data: &[u8], start: usize) -> Option<usize> {
    let mut i = start;
    while i + 1 < data.len() {
        if data[i] == b'\r' && data[i + 1] == b'\n' {
            return Some(i);
        }
        i += 1;
    }
    None
}

/// Compute MD5 ETag by streaming through a file in chunks.
pub(crate) async fn compute_file_md5(path: &std::path::Path) -> Result<String, S3Error> {
    let mut file = tokio::fs::File::open(path)
        .await
        .map_err(|e| S3Error::InternalError(e.to_string()))?;
    let mut ctx = md5::Context::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = file
            .read(&mut buf)
            .await
            .map_err(|e| S3Error::InternalError(e.to_string()))?;
        if n == 0 {
            break;
        }
        ctx.consume(&buf[..n]);
    }
    Ok(format!("\"{:x}\"", ctx.finalize()))
}
