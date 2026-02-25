use tokio::fs;

use super::{Storage, is_regular_file};
use crate::error::S3Error;

const CORS_FILE: &str = ".cors.json";

impl Storage {
    /// Store CORS configuration as JSON.
    pub async fn put_bucket_cors(&self, bucket: &str, cors_json: &[u8]) -> Result<(), S3Error> {
        self.head_bucket(bucket).await?;
        let path = self.data_dir.join(bucket).join(CORS_FILE);
        fs::write(&path, cors_json)
            .await
            .map_err(|e| S3Error::InternalError(e.to_string()))
    }

    /// Read CORS configuration. Returns raw JSON bytes.
    pub async fn get_bucket_cors(&self, bucket: &str) -> Result<Vec<u8>, S3Error> {
        self.head_bucket(bucket).await?;
        let path = self.data_dir.join(bucket).join(CORS_FILE);
        if !is_regular_file(&path).await {
            return Err(S3Error::NoSuchCORSConfiguration);
        }
        fs::read(&path)
            .await
            .map_err(|e| S3Error::InternalError(e.to_string()))
    }

    /// Delete CORS configuration.
    pub async fn delete_bucket_cors(&self, bucket: &str) -> Result<(), S3Error> {
        self.head_bucket(bucket).await?;
        let path = self.data_dir.join(bucket).join(CORS_FILE);
        if is_regular_file(&path).await {
            fs::remove_file(&path)
                .await
                .map_err(|e| S3Error::InternalError(e.to_string()))?;
        }
        Ok(())
    }
}
