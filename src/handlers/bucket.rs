use std::sync::Arc;

use hyper::{Response, StatusCode};

use super::{BoxBody, empty_response, error_response, full_body, xml_response};
use crate::storage::Storage;
use crate::storage::bucket::format_system_time;
use crate::xml::{self, BucketEntry, ListAllMyBucketsResult};

/// PUT /{bucket} — Create a new bucket.
pub async fn create_bucket(storage: Arc<Storage>, bucket: &str) -> Response<BoxBody> {
    match storage.create_bucket(bucket).await {
        Ok(()) => {
            let location = format!("/{}", bucket);
            Response::builder()
                .status(StatusCode::OK)
                .header("Location", location)
                .body(full_body(bytes::Bytes::new()))
                .unwrap()
        }
        Err(e) => error_response(e, &format!("/{}", bucket)),
    }
}

/// DELETE /{bucket} — Delete a bucket.
pub async fn delete_bucket(storage: Arc<Storage>, bucket: &str) -> Response<BoxBody> {
    match storage.delete_bucket(bucket).await {
        Ok(()) => empty_response(StatusCode::NO_CONTENT),
        Err(e) => error_response(e, &format!("/{}", bucket)),
    }
}

/// HEAD /{bucket} — Check if a bucket exists.
pub async fn head_bucket(storage: Arc<Storage>, bucket: &str) -> Response<BoxBody> {
    match storage.head_bucket(bucket).await {
        Ok(()) => empty_response(StatusCode::OK),
        Err(e) => error_response(e, &format!("/{}", bucket)),
    }
}

/// GET / — List all buckets.
pub async fn list_buckets(storage: Arc<Storage>) -> Response<BoxBody> {
    match storage.list_buckets().await {
        Ok(buckets) => {
            let entries: Vec<BucketEntry> = buckets
                .into_iter()
                .map(|b| BucketEntry {
                    name: b.name,
                    creation_date: format_system_time(b.creation_date),
                })
                .collect();

            let result = ListAllMyBucketsResult::new(entries);
            xml_response(StatusCode::OK, xml::to_xml(&result))
        }
        Err(e) => error_response(e, "/"),
    }
}
