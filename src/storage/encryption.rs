use tokio::fs;

use super::{Storage, is_regular_file};
use crate::error::S3Error;

const ENCRYPTION_FILE: &str = ".encryption.json";

impl Storage {
    /// Store bucket default encryption configuration as JSON.
    pub async fn put_bucket_encryption(
        &self,
        bucket: &str,
        config_json: &[u8],
    ) -> Result<(), S3Error> {
        self.head_bucket(bucket).await?;
        let path = self.data_dir.join(bucket).join(ENCRYPTION_FILE);
        fs::write(&path, config_json)
            .await
            .map_err(|e| S3Error::InternalError(e.to_string()))
    }

    /// Read bucket default encryption configuration. Returns raw JSON bytes.
    pub async fn get_bucket_encryption(&self, bucket: &str) -> Result<Vec<u8>, S3Error> {
        self.head_bucket(bucket).await?;
        let path = self.data_dir.join(bucket).join(ENCRYPTION_FILE);
        if !is_regular_file(&path).await {
            return Err(S3Error::ServerSideEncryptionConfigurationNotFoundError);
        }
        fs::read(&path)
            .await
            .map_err(|e| S3Error::InternalError(e.to_string()))
    }

    /// Delete bucket default encryption configuration.
    pub async fn delete_bucket_encryption(&self, bucket: &str) -> Result<(), S3Error> {
        self.head_bucket(bucket).await?;
        let path = self.data_dir.join(bucket).join(ENCRYPTION_FILE);
        if is_regular_file(&path).await {
            fs::remove_file(&path)
                .await
                .map_err(|e| S3Error::InternalError(e.to_string()))?;
        }
        Ok(())
    }
}
