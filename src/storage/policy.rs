use tokio::fs;

use super::{Storage, is_regular_file};
use crate::error::S3Error;

const POLICY_FILE: &str = ".policy.json";

impl Storage {
    /// Store a bucket policy as JSON.
    pub async fn put_bucket_policy(&self, bucket: &str, policy_json: &[u8]) -> Result<(), S3Error> {
        self.head_bucket(bucket).await?;
        let path = self.data_dir.join(bucket).join(POLICY_FILE);
        fs::write(&path, policy_json)
            .await
            .map_err(|e| S3Error::InternalError(e.to_string()))
    }

    /// Read a bucket policy. Returns raw JSON bytes.
    pub async fn get_bucket_policy(&self, bucket: &str) -> Result<Vec<u8>, S3Error> {
        self.head_bucket(bucket).await?;
        let path = self.data_dir.join(bucket).join(POLICY_FILE);
        if !is_regular_file(&path).await {
            return Err(S3Error::NoSuchBucketPolicy);
        }
        fs::read(&path)
            .await
            .map_err(|e| S3Error::InternalError(e.to_string()))
    }

    /// Delete a bucket policy.
    pub async fn delete_bucket_policy(&self, bucket: &str) -> Result<(), S3Error> {
        self.head_bucket(bucket).await?;
        let path = self.data_dir.join(bucket).join(POLICY_FILE);
        if is_regular_file(&path).await {
            fs::remove_file(&path)
                .await
                .map_err(|e| S3Error::InternalError(e.to_string()))?;
        }
        Ok(())
    }
}
