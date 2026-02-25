use std::sync::Arc;

use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};

use super::object::parse_query;
use super::{BoxBody, empty_response, error_response, read_body_limited, xml_response};
use crate::storage::Storage;
use crate::storage::versioning::VersioningStatus;
use crate::xml;

const S3_XMLNS: &str = "http://s3.amazonaws.com/doc/2006-03-01/";

/// PUT /{bucket}?versioning -- Set bucket versioning.
pub async fn put_bucket_versioning(
    storage: Arc<Storage>,
    bucket: &str,
    req: Request<Incoming>,
) -> Response<BoxBody> {
    let body = match read_body_limited(req.into_body(), 4 * 1024).await {
        Ok(data) => data,
        Err(e) => return error_response(e, &format!("/{}", bucket)),
    };

    let body_str = String::from_utf8_lossy(&body);
    let config: xml::VersioningConfiguration = match quick_xml::de::from_str(&body_str) {
        Ok(c) => c,
        Err(_) => {
            return error_response(crate::error::S3Error::MalformedXML, &format!("/{}", bucket));
        }
    };

    let status = match config.status.as_deref() {
        Some("Enabled") | Some("Suspended") => config.status.unwrap(),
        _ => return error_response(crate::error::S3Error::MalformedXML, &format!("/{}", bucket)),
    };

    match storage.put_versioning(bucket, &status).await {
        Ok(()) => empty_response(StatusCode::OK),
        Err(e) => error_response(e, &format!("/{}", bucket)),
    }
}

/// GET /{bucket}?versioning -- Get bucket versioning status.
pub async fn get_bucket_versioning(storage: Arc<Storage>, bucket: &str) -> Response<BoxBody> {
    match storage.get_versioning(bucket).await {
        Ok(status) => {
            let config = xml::VersioningConfiguration {
                xmlns: S3_XMLNS.to_string(),
                status: match status {
                    VersioningStatus::Enabled => Some("Enabled".to_string()),
                    VersioningStatus::Suspended => Some("Suspended".to_string()),
                    VersioningStatus::Unversioned => None,
                },
            };
            xml_response(StatusCode::OK, xml::to_xml(&config))
        }
        Err(e) => error_response(e, &format!("/{}", bucket)),
    }
}

/// GET /{bucket}?versions -- List object versions.
pub async fn list_object_versions(
    storage: Arc<Storage>,
    bucket: &str,
    query: &str,
) -> Response<BoxBody> {
    let params = parse_query(query);
    let prefix = params.get("prefix").map(|s| s.as_str()).unwrap_or("");
    let key_marker = params.get("key-marker").map(|s| s.as_str()).unwrap_or("");
    let version_id_marker = params
        .get("version-id-marker")
        .map(|s| s.as_str())
        .unwrap_or("");
    let max_keys: usize = params
        .get("max-keys")
        .and_then(|s| s.parse().ok())
        .unwrap_or(1000)
        .min(1000);
    let delimiter = params.get("delimiter").map(|s| s.as_str()).unwrap_or("");

    match storage
        .list_all_versions(
            bucket,
            prefix,
            key_marker,
            version_id_marker,
            max_keys,
            delimiter,
        )
        .await
    {
        Ok(result) => {
            let xml_result = xml::ListVersionsResult {
                xmlns: S3_XMLNS,
                name: bucket.to_string(),
                prefix: prefix.to_string(),
                key_marker: key_marker.to_string(),
                version_id_marker: version_id_marker.to_string(),
                max_keys,
                is_truncated: result.is_truncated,
                versions: result
                    .versions
                    .into_iter()
                    .map(|v| xml::VersionEntry {
                        key: v.key,
                        version_id: v.version_id,
                        is_latest: v.is_latest,
                        last_modified: v.last_modified,
                        etag: v.etag,
                        size: v.size,
                        storage_class: "STANDARD".to_string(),
                    })
                    .collect(),
                delete_markers: result
                    .delete_markers
                    .into_iter()
                    .map(|d| xml::DeleteMarkerEntry {
                        key: d.key,
                        version_id: d.version_id,
                        is_latest: d.is_latest,
                        last_modified: d.last_modified,
                    })
                    .collect(),
                common_prefixes: result
                    .common_prefixes
                    .into_iter()
                    .map(|p| xml::CommonPrefix { prefix: p })
                    .collect(),
            };
            xml_response(StatusCode::OK, xml::to_xml(&xml_result))
        }
        Err(e) => error_response(e, &format!("/{}", bucket)),
    }
}
