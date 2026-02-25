pub mod bucket;
pub mod cors;
pub mod encryption;
pub mod multipart;
pub mod object;
pub mod policy;
pub mod versioning;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::{Response, StatusCode};

use crate::error::S3Error;
use crate::xml;

/// Type-erased body that can hold either Full<Bytes> or a streaming body.
pub type BoxBody = http_body_util::combinators::BoxBody<Bytes, std::io::Error>;

/// Wrap a Full<Bytes> body into our BoxBody type.
pub fn full_body(data: impl Into<Bytes>) -> BoxBody {
    Full::new(data.into())
        .map_err(|never| match never {})
        .boxed()
}

/// Build a response with the given status and body.
pub fn response(status: StatusCode, body: impl Into<Bytes>) -> Response<BoxBody> {
    Response::builder()
        .status(status)
        .body(full_body(body))
        .unwrap()
}

/// Build an XML response with the given status.
pub fn xml_response(status: StatusCode, xml: String) -> Response<BoxBody> {
    Response::builder()
        .status(status)
        .header("Content-Type", "application/xml")
        .body(full_body(xml))
        .unwrap()
}

/// Build an empty response with the given status.
pub fn empty_response(status: StatusCode) -> Response<BoxBody> {
    Response::builder()
        .status(status)
        .body(full_body(Bytes::new()))
        .unwrap()
}

/// Build a JSON response with the given status.
pub fn json_response(status: StatusCode, json: String) -> Response<BoxBody> {
    Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        .body(full_body(json))
        .unwrap()
}

/// Build an S3 XML error response.
pub fn error_response(err: S3Error, resource: &str) -> Response<BoxBody> {
    let (code, status, message) = err.as_s3_error();
    let error_xml = xml::S3ErrorResponse {
        code: code.to_string(),
        message: message.to_string(),
        resource: resource.to_string(),
        request_id: uuid::Uuid::new_v4().to_string(),
    };
    xml_response(status, xml::to_xml(&error_xml))
}

/// Build a 200 OK response with only an ETag header.
pub fn etag_response(etag: &str) -> Response<BoxBody> {
    Response::builder()
        .status(StatusCode::OK)
        .header("ETag", etag)
        .body(full_body(bytes::Bytes::new()))
        .unwrap()
}

/// Read request body up to `max_bytes`. Returns EntityTooLarge if exceeded.
pub async fn read_body_limited(mut body: Incoming, max_bytes: usize) -> Result<Vec<u8>, S3Error> {
    let mut collected = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|e| S3Error::InternalError(e.to_string()))?;
        if let Ok(data) = frame.into_data() {
            collected.extend_from_slice(&data);
            if collected.len() > max_bytes {
                return Err(S3Error::EntityTooLarge);
            }
        }
    }
    Ok(collected)
}
