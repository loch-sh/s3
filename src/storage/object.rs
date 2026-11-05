use std::collections::{BTreeSet, HashMap};
use std::path::PathBuf;
use std::time::SystemTime;

use http_body_util::BodyExt;
use hyper::body::Incoming;
use serde::{Deserialize, Serialize};
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::{INTERNAL_NAMES, Storage, guess_content_type, is_regular_file};
use crate::encryption::EncryptionMeta;
use crate::error::S3Error;
use crate::quota::{Reservation, file_size};

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
    /// User ID of the object owner.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
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
        mut reservation: Reservation,
    ) -> Result<String, S3Error> {
        self.head_bucket(bucket).await?;

        let object_path = self.object_path(bucket, key)?;
        if let Some(parent) = object_path.parent() {
            fs::create_dir_all(parent)
                .await
                .map_err(|e| S3Error::InternalError(e.to_string()))?;
        }

        // UUID-based temp file to prevent TOCTOU race conditions
        let tmp_path = self.tmp_file();
        let mut file = tokio::fs::File::create(&tmp_path)
            .await
            .map_err(|e| S3Error::InternalError(e.to_string()))?;

        let (etag, written) =
            match stream_body_to_file(&mut file, body, aws_chunked, &mut reservation).await {
                Ok(r) => r,
                Err(e) => {
                    drop(file);
                    let _ = fs::remove_file(&tmp_path).await;
                    return Err(e);
                }
            };
        drop(file);

        {
            let _path_guard = self.quota.lock_path(&object_path).await;
            let replaced = file_size(&object_path).await;
            if let Err(e) = fs::rename(&tmp_path, &object_path).await {
                let _ = fs::remove_file(&tmp_path).await;
                return Err(S3Error::InternalError(e.to_string()));
            }
            reservation.commit(written);
            self.quota.release(replaced);
        }

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
            {
                let _path_guard = self.quota.lock_path(&object_path).await;
                let size = file_size(&object_path).await;
                match fs::remove_file(&object_path).await {
                    Ok(()) => self.quota.release(size),
                    // Removed concurrently: already released by the other request
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => return Err(S3Error::InternalError(e.to_string())),
                }
            }

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
        let tmp_path = self.tmp_file();
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
        let tmp_path = self.tmp_file();
        fs::write(&tmp_path, &json)
            .await
            .map_err(|e| S3Error::InternalError(e.to_string()))?;
        if let Err(e) = fs::rename(&tmp_path, &meta_path).await {
            let _ = fs::remove_file(&tmp_path).await;
            return Err(S3Error::InternalError(e.to_string()));
        }
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
        if INTERNAL_NAMES.contains(&name.as_str()) {
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
/// If `aws_chunked` is true, the body is decoded from the AWS chunked transfer
/// encoding on the fly (constant memory; trailing headers such as
/// `x-amz-checksum-*` are ignored).
/// Bytes are reserved against the storage quota before being written: the
/// upload stops with `QuotaExceeded` as soon as the quota would be crossed.
/// Returns the MD5 ETag (quoted hex digest) and the number of bytes written.
pub(crate) async fn stream_body_to_file(
    file: &mut tokio::fs::File,
    mut body: Incoming,
    aws_chunked: bool,
    reservation: &mut Reservation,
) -> Result<(String, u64), S3Error> {
    let mut md5_ctx = md5::Context::new();
    let mut decoder = aws_chunked.then(AwsChunkedDecoder::new);
    let mut decoded = Vec::new();
    let mut total: u64 = 0;

    loop {
        // A client that stops sending must not hold its quota reservation forever
        let frame = match tokio::time::timeout(BODY_IDLE_TIMEOUT, body.frame()).await {
            Ok(Some(frame)) => frame,
            Ok(None) => break,
            Err(_) => return Err(S3Error::RequestTimeout),
        };
        let frame = frame.map_err(|e| S3Error::InternalError(e.to_string()))?;
        let Ok(data) = frame.into_data() else {
            continue;
        };
        let payload: &[u8] = match decoder.as_mut() {
            Some(dec) => {
                decoded.clear();
                dec.feed(&data, &mut decoded)?;
                &decoded
            }
            None => &data,
        };
        if payload.is_empty() {
            continue;
        }
        reservation.ensure(total + payload.len() as u64)?;
        md5_ctx.consume(payload);
        file.write_all(payload)
            .await
            .map_err(|e| S3Error::InternalError(e.to_string()))?;
        total += payload.len() as u64;
    }

    if let Some(dec) = decoder {
        if !dec.is_complete() {
            return Err(S3Error::InvalidArgument(
                "Incomplete aws-chunked body (missing final chunk).".to_string(),
            ));
        }
    }

    file.flush()
        .await
        .map_err(|e| S3Error::InternalError(e.to_string()))?;

    Ok((format!("\"{:x}\"", md5_ctx.finalize()), total))
}

/// Maximum time without receiving any body data before an upload is aborted.
const BODY_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// Maximum length of a chunk-size line (`<hex>;chunk-signature=<64 hex>`).
const MAX_CHUNK_HEADER: usize = 4096;

enum ChunkState {
    /// Reading a `<hex-size>[;extensions]\r\n` line.
    Header,
    /// Reading chunk data; bytes remaining.
    Data(u64),
    /// Expecting the `\r\n` after chunk data; bytes remaining (2 then 1).
    DataEnd(u8),
    /// Final 0-size chunk seen: trailers (checksums, trailer signature) are ignored.
    Done,
}

/// Incremental decoder for the AWS chunked transfer encoding
/// (`<hex-size>[;ext]\r\n<data>\r\n ... 0[;ext]\r\n[trailers]\r\n`).
struct AwsChunkedDecoder {
    state: ChunkState,
    header: Vec<u8>,
}

impl AwsChunkedDecoder {
    fn new() -> Self {
        Self {
            state: ChunkState::Header,
            header: Vec::new(),
        }
    }

    /// True once the final zero-size chunk has been read.
    fn is_complete(&self) -> bool {
        matches!(self.state, ChunkState::Done)
    }

    /// Decode `input`, appending payload bytes to `out`.
    fn feed(&mut self, mut input: &[u8], out: &mut Vec<u8>) -> Result<(), S3Error> {
        let malformed = || S3Error::InvalidArgument("Malformed aws-chunked body.".to_string());
        while !input.is_empty() {
            match self.state {
                ChunkState::Header => {
                    let Some(pos) = input.iter().position(|&b| b == b'\n') else {
                        self.header.extend_from_slice(input);
                        if self.header.len() > MAX_CHUNK_HEADER {
                            return Err(malformed());
                        }
                        return Ok(());
                    };
                    self.header.extend_from_slice(&input[..pos]);
                    input = &input[pos + 1..];
                    if self.header.len() > MAX_CHUNK_HEADER {
                        return Err(malformed());
                    }
                    let line = std::str::from_utf8(&self.header).map_err(|_| malformed())?;
                    let line = line.strip_suffix('\r').unwrap_or(line);
                    let size_str = line.split(';').next().unwrap_or("").trim();
                    let size = u64::from_str_radix(size_str, 16).map_err(|_| malformed())?;
                    self.header.clear();
                    self.state = if size == 0 {
                        ChunkState::Done
                    } else {
                        ChunkState::Data(size)
                    };
                }
                ChunkState::Data(remaining) => {
                    let n = remaining.min(input.len() as u64) as usize;
                    out.extend_from_slice(&input[..n]);
                    input = &input[n..];
                    self.state = if remaining == n as u64 {
                        ChunkState::DataEnd(2)
                    } else {
                        ChunkState::Data(remaining - n as u64)
                    };
                }
                ChunkState::DataEnd(remaining) => {
                    let expected = if remaining == 2 { b'\r' } else { b'\n' };
                    if input[0] != expected {
                        return Err(malformed());
                    }
                    input = &input[1..];
                    self.state = if remaining == 1 {
                        ChunkState::Header
                    } else {
                        ChunkState::DataEnd(1)
                    };
                }
                ChunkState::Done => return Ok(()),
            }
        }
        Ok(())
    }
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

#[cfg(test)]
mod aws_chunked_tests {
    use super::AwsChunkedDecoder;

    fn decode_in_pieces(body: &[u8], piece: usize) -> Vec<u8> {
        let mut dec = AwsChunkedDecoder::new();
        let mut out = Vec::new();
        for chunk in body.chunks(piece) {
            dec.feed(chunk, &mut out).unwrap();
        }
        out
    }

    #[test]
    fn test_decode_signed_chunks_with_trailer() {
        let sig = "a".repeat(64);
        let body = format!(
            "5;chunk-signature={sig}\r\nhello\r\n6;chunk-signature={sig}\r\n world\r\n0;chunk-signature={sig}\r\nx-amz-checksum-crc64nvme:AAAAAAAAAAA=\r\n\r\n"
        );
        for piece in [1, 2, 3, 7, 64, body.len()] {
            assert_eq!(decode_in_pieces(body.as_bytes(), piece), b"hello world");
        }
    }

    #[test]
    fn test_decode_unsigned_chunks() {
        let body = b"3\r\nabc\r\n0\r\n\r\n";
        assert_eq!(decode_in_pieces(body, 1), b"abc");
    }

    #[test]
    fn test_decode_requires_crlf_and_final_chunk() {
        let mut out = Vec::new();
        assert!(
            AwsChunkedDecoder::new()
                .feed(b"3\r\nabcXY4\r\n", &mut out)
                .is_err()
        );
        let mut dec = AwsChunkedDecoder::new();
        dec.feed(b"3\r\nabc\r\n", &mut out).unwrap();
        assert!(!dec.is_complete());
        dec.feed(b"0\r\n\r\n", &mut out).unwrap();
        assert!(dec.is_complete());
    }

    #[test]
    fn test_decode_rejects_malformed_header() {
        let mut dec = AwsChunkedDecoder::new();
        let mut out = Vec::new();
        assert!(dec.feed(b"zz\r\nabc", &mut out).is_err());
        let mut dec = AwsChunkedDecoder::new();
        assert!(dec.feed(&vec![b'1'; 5000], &mut out).is_err());
    }
}
