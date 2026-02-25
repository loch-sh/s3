use quick_xml::se::Serializer;
use serde::{Deserialize, Serialize};

pub const S3_XMLNS: &str = "http://s3.amazonaws.com/doc/2006-03-01/";

/// Serialize a value to an S3-compatible XML string with XML prologue.
pub fn to_xml<T: Serialize>(value: &T) -> String {
    let mut buffer = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
    let mut ser = Serializer::new(&mut buffer);
    ser.set_quote_level(quick_xml::se::QuoteLevel::Full);
    value.serialize(ser).expect("XML serialization failed");
    buffer
}

// -- ListBuckets response --

#[derive(Serialize)]
#[serde(rename = "ListAllMyBucketsResult")]
pub struct ListAllMyBucketsResult {
    #[serde(rename = "@xmlns")]
    pub xmlns: &'static str,
    #[serde(rename = "Owner")]
    pub owner: Owner,
    #[serde(rename = "Buckets")]
    pub buckets: Buckets,
}

#[derive(Serialize)]
pub struct Owner {
    #[serde(rename = "ID")]
    pub id: String,
    #[serde(rename = "DisplayName")]
    pub display_name: String,
}

#[derive(Serialize)]
pub struct Buckets {
    #[serde(rename = "Bucket", default)]
    pub bucket: Vec<BucketEntry>,
}

#[derive(Serialize)]
pub struct BucketEntry {
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "CreationDate")]
    pub creation_date: String,
}

impl ListAllMyBucketsResult {
    pub fn new(buckets: Vec<BucketEntry>) -> Self {
        Self {
            xmlns: S3_XMLNS,
            owner: Owner {
                id: "1".to_string(),
                display_name: "loch".to_string(),
            },
            buckets: Buckets { bucket: buckets },
        }
    }
}

// -- ListObjectsV2 response --

#[derive(Serialize)]
#[serde(rename = "ListBucketResult")]
pub struct ListBucketResult {
    #[serde(rename = "@xmlns")]
    pub xmlns: &'static str,
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "Prefix")]
    pub prefix: String,
    #[serde(rename = "Delimiter")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delimiter: Option<String>,
    #[serde(rename = "KeyCount")]
    pub key_count: usize,
    #[serde(rename = "MaxKeys")]
    pub max_keys: usize,
    #[serde(rename = "IsTruncated")]
    pub is_truncated: bool,
    #[serde(rename = "NextContinuationToken")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_continuation_token: Option<String>,
    #[serde(rename = "Contents")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub contents: Vec<ObjectEntry>,
    #[serde(rename = "CommonPrefixes")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub common_prefixes: Vec<CommonPrefix>,
}

#[derive(Serialize)]
pub struct ObjectEntry {
    #[serde(rename = "Key")]
    pub key: String,
    #[serde(rename = "LastModified")]
    pub last_modified: String,
    #[serde(rename = "ETag")]
    pub etag: String,
    #[serde(rename = "Size")]
    pub size: u64,
    #[serde(rename = "StorageClass")]
    pub storage_class: String,
}

#[derive(Serialize)]
pub struct CommonPrefix {
    #[serde(rename = "Prefix")]
    pub prefix: String,
}

impl ListBucketResult {
    pub fn new(name: String, prefix: String) -> Self {
        Self {
            xmlns: S3_XMLNS,
            name,
            prefix,
            delimiter: None,
            key_count: 0,
            max_keys: 1000,
            is_truncated: false,
            next_continuation_token: None,
            contents: Vec::new(),
            common_prefixes: Vec::new(),
        }
    }
}

// -- CopyObject response --

#[derive(Serialize)]
#[serde(rename = "CopyObjectResult")]
pub struct CopyObjectResult {
    #[serde(rename = "LastModified")]
    pub last_modified: String,
    #[serde(rename = "ETag")]
    pub etag: String,
}

// -- Error response --

#[derive(Serialize)]
#[serde(rename = "Error")]
pub struct S3ErrorResponse {
    #[serde(rename = "Code")]
    pub code: String,
    #[serde(rename = "Message")]
    pub message: String,
    #[serde(rename = "Resource")]
    pub resource: String,
    #[serde(rename = "RequestId")]
    pub request_id: String,
}

// -- Multipart upload --

#[derive(Serialize)]
#[serde(rename = "InitiateMultipartUploadResult")]
pub struct InitiateMultipartUploadResult {
    #[serde(rename = "@xmlns")]
    pub xmlns: &'static str,
    #[serde(rename = "Bucket")]
    pub bucket: String,
    #[serde(rename = "Key")]
    pub key: String,
    #[serde(rename = "UploadId")]
    pub upload_id: String,
}

#[derive(Deserialize)]
#[serde(rename = "CompleteMultipartUpload")]
pub struct CompleteMultipartUploadRequest {
    #[serde(rename = "Part", default)]
    pub parts: Vec<CompletePart>,
}

#[derive(Deserialize)]
pub struct CompletePart {
    #[serde(rename = "PartNumber")]
    pub part_number: u32,
    #[serde(rename = "ETag")]
    pub etag: String,
}

#[derive(Serialize)]
#[serde(rename = "CompleteMultipartUploadResult")]
pub struct CompleteMultipartUploadResult {
    #[serde(rename = "@xmlns")]
    pub xmlns: &'static str,
    #[serde(rename = "Location")]
    pub location: String,
    #[serde(rename = "Bucket")]
    pub bucket: String,
    #[serde(rename = "Key")]
    pub key: String,
    #[serde(rename = "ETag")]
    pub etag: String,
}

#[derive(Serialize)]
#[serde(rename = "ListPartsResult")]
pub struct ListPartsResult {
    #[serde(rename = "@xmlns")]
    pub xmlns: &'static str,
    #[serde(rename = "Bucket")]
    pub bucket: String,
    #[serde(rename = "Key")]
    pub key: String,
    #[serde(rename = "UploadId")]
    pub upload_id: String,
    #[serde(rename = "IsTruncated")]
    pub is_truncated: bool,
    #[serde(rename = "Part")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub parts: Vec<PartEntry>,
}

#[derive(Serialize)]
pub struct PartEntry {
    #[serde(rename = "PartNumber")]
    pub part_number: u32,
    #[serde(rename = "LastModified")]
    pub last_modified: String,
    #[serde(rename = "ETag")]
    pub etag: String,
    #[serde(rename = "Size")]
    pub size: u64,
}

#[derive(Serialize)]
#[serde(rename = "ListMultipartUploadsResult")]
pub struct ListMultipartUploadsResult {
    #[serde(rename = "@xmlns")]
    pub xmlns: &'static str,
    #[serde(rename = "Bucket")]
    pub bucket: String,
    #[serde(rename = "IsTruncated")]
    pub is_truncated: bool,
    #[serde(rename = "Upload")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub uploads: Vec<UploadEntry>,
}

#[derive(Serialize)]
pub struct UploadEntry {
    #[serde(rename = "Key")]
    pub key: String,
    #[serde(rename = "UploadId")]
    pub upload_id: String,
    #[serde(rename = "Initiated")]
    pub initiated: String,
}

// -- Versioning --

#[derive(Serialize, Deserialize)]
#[serde(rename = "VersioningConfiguration")]
pub struct VersioningConfiguration {
    #[serde(rename = "@xmlns", default)]
    pub xmlns: String,
    #[serde(rename = "Status")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub status: Option<String>,
}

#[derive(Serialize)]
#[serde(rename = "ListVersionsResult")]
pub struct ListVersionsResult {
    #[serde(rename = "@xmlns")]
    pub xmlns: &'static str,
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "Prefix")]
    pub prefix: String,
    #[serde(rename = "KeyMarker")]
    pub key_marker: String,
    #[serde(rename = "VersionIdMarker")]
    pub version_id_marker: String,
    #[serde(rename = "MaxKeys")]
    pub max_keys: usize,
    #[serde(rename = "IsTruncated")]
    pub is_truncated: bool,
    #[serde(rename = "Version")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub versions: Vec<VersionEntry>,
    #[serde(rename = "DeleteMarker")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub delete_markers: Vec<DeleteMarkerEntry>,
    #[serde(rename = "CommonPrefixes")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub common_prefixes: Vec<CommonPrefix>,
}

#[derive(Serialize)]
pub struct VersionEntry {
    #[serde(rename = "Key")]
    pub key: String,
    #[serde(rename = "VersionId")]
    pub version_id: String,
    #[serde(rename = "IsLatest")]
    pub is_latest: bool,
    #[serde(rename = "LastModified")]
    pub last_modified: String,
    #[serde(rename = "ETag")]
    pub etag: String,
    #[serde(rename = "Size")]
    pub size: u64,
    #[serde(rename = "StorageClass")]
    pub storage_class: String,
}

#[derive(Serialize)]
pub struct DeleteMarkerEntry {
    #[serde(rename = "Key")]
    pub key: String,
    #[serde(rename = "VersionId")]
    pub version_id: String,
    #[serde(rename = "IsLatest")]
    pub is_latest: bool,
    #[serde(rename = "LastModified")]
    pub last_modified: String,
}

// -- Server-Side Encryption Configuration --

#[derive(Serialize, Deserialize)]
#[serde(rename = "ServerSideEncryptionConfiguration")]
pub struct ServerSideEncryptionConfiguration {
    #[serde(rename = "@xmlns", default)]
    pub xmlns: String,
    #[serde(rename = "Rule")]
    pub rule: ServerSideEncryptionRule,
}

#[derive(Serialize, Deserialize)]
pub struct ServerSideEncryptionRule {
    #[serde(rename = "ApplyServerSideEncryptionByDefault")]
    pub apply_default: ApplyServerSideEncryptionByDefault,
    #[serde(rename = "BucketKeyEnabled")]
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bucket_key_enabled: Option<bool>,
}

#[derive(Serialize, Deserialize)]
pub struct ApplyServerSideEncryptionByDefault {
    #[serde(rename = "SSEAlgorithm")]
    pub sse_algorithm: String,
}
