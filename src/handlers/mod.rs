pub mod bucket;
pub mod cors;
pub mod encryption;
pub mod health;
pub mod multipart;
pub mod object;
pub mod policy;
pub mod users;
pub mod versioning;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};

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

/// Body integrity check attached to the request by the router after
/// authentication (`PayloadCheck::None` when absent).
pub fn payload_check(req: &Request<Incoming>) -> crate::auth::PayloadCheck {
    req.extensions()
        .get::<crate::auth::PayloadCheck>()
        .cloned()
        .unwrap_or_default()
}

/// Read a request body up to `max_bytes` (EntityTooLarge if exceeded),
/// decoding aws-chunked bodies and enforcing the signed payload hash or
/// chunk signatures.
pub async fn read_body_limited(
    req: Request<Incoming>,
    max_bytes: usize,
) -> Result<Vec<u8>, S3Error> {
    let check = payload_check(&req);
    let aws_chunked = crate::handlers::object::is_aws_chunked(&req);
    let mut body = req.into_body();
    let mut reader = crate::storage::object::BodyReader::new(aws_chunked, check);
    let mut collected = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|e| S3Error::InternalError(e.to_string()))?;
        if let Ok(data) = frame.into_data() {
            reader.feed(&data, &mut collected)?;
            if collected.len() > max_bytes {
                return Err(S3Error::EntityTooLarge);
            }
        }
    }
    reader.finish()?;
    Ok(collected)
}
