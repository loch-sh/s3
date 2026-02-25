use std::path::PathBuf;

use tokio::fs;

use super::{Storage, is_regular_file};
use crate::error::S3Error;

const BUCKET_ACL_FILE: &str = ".acl.xml";
const ACL_DIR: &str = ".acl";

impl Storage {
    /// Store a bucket-level ACL.
    pub async fn put_bucket_acl(&self, bucket: &str, acl_xml: &[u8]) -> Result<(), S3Error> {
        self.head_bucket(bucket).await?;
        let path = self.data_dir.join(bucket).join(BUCKET_ACL_FILE);
        fs::write(&path, acl_xml)
            .await
            .map_err(|e| S3Error::InternalError(e.to_string()))
    }

    /// Read a bucket-level ACL. Returns None if no ACL has been set.
    pub async fn get_bucket_acl(&self, bucket: &str) -> Result<Option<Vec<u8>>, S3Error> {
        self.head_bucket(bucket).await?;
        let path = self.data_dir.join(bucket).join(BUCKET_ACL_FILE);
        if !is_regular_file(&path).await {
            return Ok(None);
        }
        fs::read(&path)
            .await
            .map(Some)
            .map_err(|e| S3Error::InternalError(e.to_string()))
    }

    /// Store an object-level ACL.
    pub async fn put_object_acl(
        &self,
        bucket: &str,
        key: &str,
        acl_xml: &[u8],
    ) -> Result<(), S3Error> {
        // Verify the object exists
        let _ = self.head_object(bucket, key).await?;
        let acl_path = self.object_acl_path(bucket, key)?;
        if let Some(parent) = acl_path.parent() {
            fs::create_dir_all(parent)
                .await
                .map_err(|e| S3Error::InternalError(e.to_string()))?;
        }
        fs::write(&acl_path, acl_xml)
            .await
            .map_err(|e| S3Error::InternalError(e.to_string()))
    }

    /// Read an object-level ACL. Returns None if no ACL has been set.
    pub async fn get_object_acl(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<Option<Vec<u8>>, S3Error> {
        let _ = self.head_object(bucket, key).await?;
        let acl_path = self.object_acl_path(bucket, key)?;
        if !is_regular_file(&acl_path).await {
            return Ok(None);
        }
        fs::read(&acl_path)
            .await
            .map(Some)
            .map_err(|e| S3Error::InternalError(e.to_string()))
    }

    /// Delete an object's ACL file and clean up empty parent directories.
    pub async fn delete_object_acl(&self, bucket: &str, key: &str) -> Result<(), S3Error> {
        let acl_path = self.object_acl_path(bucket, key)?;
        if is_regular_file(&acl_path).await {
            let _ = fs::remove_file(&acl_path).await;
            // Clean up empty parent directories up to .acl/
            let acl_root = self.data_dir.join(bucket).join(ACL_DIR);
            let mut current = acl_path.parent().map(|p| p.to_path_buf());
            while let Some(dir) = current {
                if dir == acl_root {
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

    /// Path to an object's ACL file: {bucket}/.acl/{key}.xml
    fn object_acl_path(&self, bucket: &str, key: &str) -> Result<PathBuf, S3Error> {
        let bucket_dir = self.data_dir.join(bucket);
        let acl_path = bucket_dir.join(ACL_DIR).join(format!("{}.xml", key));
        Ok(acl_path)
    }
}
