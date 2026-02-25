use std::time::SystemTime;

use chrono::{DateTime, Utc};
use tokio::fs;

use super::{INTERNAL_NAMES, Storage, is_real_dir};
use crate::error::S3Error;

/// Metadata about a bucket.
pub struct BucketInfo {
    pub name: String,
    pub creation_date: SystemTime,
}

const METADATA_FILE: &str = ".metadata";

impl Storage {
    /// Create a new bucket directory with a metadata file.
    pub async fn create_bucket(&self, name: &str) -> Result<(), S3Error> {
        let bucket_path = self.safe_bucket_path(name)?;
        // Use symlink_metadata to avoid following symlinks
        if fs::symlink_metadata(&bucket_path).await.is_ok() {
            return Err(S3Error::BucketAlreadyExists);
        }
        fs::create_dir_all(&bucket_path)
            .await
            .map_err(|e| S3Error::InternalError(e.to_string()))?;

        // Write minimal metadata (creation timestamp)
        let now = format_system_time(SystemTime::now());
        let metadata = format!("{{\"created\":\"{}\"}}", now);
        fs::write(bucket_path.join(METADATA_FILE), metadata)
            .await
            .map_err(|e| S3Error::InternalError(e.to_string()))?;

        Ok(())
    }

    /// Delete a bucket. Fails if the bucket is not empty.
    pub async fn delete_bucket(&self, name: &str) -> Result<(), S3Error> {
        let bucket_path = self.safe_bucket_path(name)?;
        if !is_real_dir(&bucket_path).await {
            return Err(S3Error::NoSuchBucket);
        }

        // Check if bucket contains anything other than internal files
        let mut entries = fs::read_dir(&bucket_path)
            .await
            .map_err(|e| S3Error::InternalError(e.to_string()))?;

        while let Some(entry) = entries
            .next_entry()
            .await
            .map_err(|e| S3Error::InternalError(e.to_string()))?
        {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if !INTERNAL_NAMES.contains(&name_str.as_ref()) {
                return Err(S3Error::BucketNotEmpty);
            }
        }

        fs::remove_dir_all(&bucket_path)
            .await
            .map_err(|e| S3Error::InternalError(e.to_string()))?;

        Ok(())
    }

    /// Check if a bucket exists (must be a real directory, not a symlink).
    pub async fn head_bucket(&self, name: &str) -> Result<(), S3Error> {
        let bucket_path = self.safe_bucket_path(name)?;
        if is_real_dir(&bucket_path).await {
            Ok(())
        } else {
            Err(S3Error::NoSuchBucket)
        }
    }

    /// List all buckets.
    pub async fn list_buckets(&self) -> Result<Vec<BucketInfo>, S3Error> {
        let mut buckets = Vec::new();
        let mut entries = fs::read_dir(&self.data_dir)
            .await
            .map_err(|e| S3Error::InternalError(e.to_string()))?;

        while let Some(entry) = entries
            .next_entry()
            .await
            .map_err(|e| S3Error::InternalError(e.to_string()))?
        {
            // Use symlink_metadata to not follow symlinks
            let meta = match fs::symlink_metadata(entry.path()).await {
                Ok(m) => m,
                Err(_) => continue,
            };

            // Only include real directories (not symlinks)
            if meta.is_dir() && !meta.file_type().is_symlink() {
                let creation_date = read_bucket_creation_date(&entry.path()).await;
                buckets.push(BucketInfo {
                    name: entry.file_name().to_string_lossy().to_string(),
                    creation_date,
                });
            }
        }

        buckets.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(buckets)
    }
}

/// Read the creation date from a bucket's .metadata file.
/// Falls back to the directory's filesystem creation time if the file is missing.
async fn read_bucket_creation_date(bucket_path: &std::path::Path) -> SystemTime {
    let metadata_path = bucket_path.join(METADATA_FILE);
    if let Ok(content) = fs::read_to_string(&metadata_path).await {
        if let Some(start) = content.find("\"created\":\"") {
            let rest = &content[start + 11..];
            if let Some(end) = rest.find('"') {
                let date_str = &rest[..end];
                if let Ok(dt) = DateTime::parse_from_rfc3339(date_str) {
                    return dt.to_utc().into();
                }
            }
        }
    }
    // Fallback to filesystem metadata
    if let Ok(meta) = fs::metadata(bucket_path).await {
        meta.created().unwrap_or(SystemTime::UNIX_EPOCH)
    } else {
        SystemTime::UNIX_EPOCH
    }
}

/// Format a SystemTime as an ISO 8601 string (e.g. "2024-01-15T10:30:00.000Z").
pub fn format_system_time(time: SystemTime) -> String {
    let dt: DateTime<Utc> = time.into();
    dt.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}
