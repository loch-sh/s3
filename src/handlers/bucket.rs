use std::sync::Arc;

use hyper::{Response, StatusCode};

use super::{BoxBody, empty_response, error_response, full_body, xml_response};
use crate::policy::S3Action;
use crate::storage::Storage;
use crate::storage::bucket::format_system_time;
use crate::users::UserStore;
use crate::xml::{self, BucketEntry, ListAllMyBucketsResult};

/// PUT /{bucket} — Create a new bucket.
pub async fn create_bucket(
    storage: Arc<Storage>,
    bucket: &str,
    owner: Option<&str>,
) -> Response<BoxBody> {
    match storage.create_bucket(bucket, owner).await {
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

/// GET / — List buckets visible to the caller.
/// - Root (or no auth): all buckets.
/// - Non-root: buckets they own + buckets where they have s3:ListBucket via policy.
pub async fn list_buckets(
    storage: Arc<Storage>,
    caller_user_id: Option<&str>,
    is_root: bool,
) -> Response<BoxBody> {
    let all_buckets = match storage.list_buckets().await {
        Ok(b) => b,
        Err(e) => return error_response(e, "/"),
    };

    let entries: Vec<BucketEntry> = if is_root || caller_user_id.is_none() {
        all_buckets
            .into_iter()
            .map(|b| BucketEntry {
                name: b.name,
                creation_date: format_system_time(b.creation_date),
            })
            .collect()
    } else {
        let user_id = caller_user_id.unwrap();
        let user_arn = UserStore::arn_for(user_id);
        let mut visible = Vec::new();
        for b in all_buckets {
            // Include if owner
            if b.owner.as_deref() == Some(user_id) {
                visible.push(BucketEntry {
                    name: b.name,
                    creation_date: format_system_time(b.creation_date),
                });
                continue;
            }
            // Include if s3:ListBucket is allowed via policy
            let resource = format!("arn:aws:s3:::{}", b.name);
            let allowed = match storage.get_bucket_policy(&b.name).await {
                Ok(data) => match serde_json::from_slice::<crate::policy::BucketPolicy>(&data) {
                    Ok(policy) => {
                        policy.is_allowed_for_user(&user_arn, S3Action::ListBucket, &resource)
                    }
                    Err(_) => false,
                },
                Err(_) => false,
            };
            if allowed {
                visible.push(BucketEntry {
                    name: b.name,
                    creation_date: format_system_time(b.creation_date),
                });
            }
        }
        visible
    };

    let result = ListAllMyBucketsResult::new(entries);
    xml_response(StatusCode::OK, xml::to_xml(&result))
}
