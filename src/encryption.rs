use std::path::Path;

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use hkdf::Hkdf;
use hyper::header::HeaderMap;
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::error::S3Error;

/// Chunk size for streaming encryption (1 MiB plaintext).
pub const CHUNK_SIZE: usize = 1_048_576;
/// AES-GCM authentication tag size (included in ciphertext).
const TAG_SIZE: usize = 16;

/// HKDF info string for SSE-S3 key derivation.
const HKDF_INFO: &[u8] = b"loch-s3-sse-s3";

/// Encryption algorithm marker stored in metadata.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum SseAlgorithm {
    /// SSE-S3: server-managed key (AES256).
    #[serde(rename = "AES256")]
    SseS3,
    /// SSE-C: customer-provided key.
    #[serde(rename = "SSE-C")]
    SseC,
}

/// Encryption parameters persisted in the metadata sidecar.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EncryptionMeta {
    pub algorithm: SseAlgorithm,
    /// Base64-encoded 12-byte nonce for AES-GCM.
    pub nonce: String,
    /// Base64-encoded 32-byte HKDF salt (SSE-S3 only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_salt: Option<String>,
    /// Base64-encoded MD5 of the customer key (SSE-C only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub customer_key_md5: Option<String>,
    /// Original plaintext size in bytes.
    pub plaintext_size: u64,
}

/// Server encryption configuration loaded from environment.
#[derive(Clone)]
pub struct EncryptionConfig {
    pub master_key: [u8; 32],
}

/// Parsed SSE request from HTTP headers.
pub enum SseRequest {
    /// No encryption requested.
    None,
    /// SSE-S3 requested (x-amz-server-side-encryption: AES256).
    SseS3,
    /// SSE-C requested with customer key.
    SseC { key: [u8; 32], key_md5: String },
}

/// Parsed SSE-C headers for a CopyObject source.
pub struct SseCCopySource {
    pub key: [u8; 32],
    pub key_md5: String,
}

/// Parse SSE headers from a request.
///
/// Handles both SSE-S3 (`x-amz-server-side-encryption: AES256`) and SSE-C
/// (`x-amz-server-side-encryption-customer-algorithm/key/key-MD5`).
pub fn parse_sse_headers(headers: &HeaderMap) -> Result<SseRequest, S3Error> {
    let sse_header = headers
        .get("x-amz-server-side-encryption")
        .and_then(|v| v.to_str().ok());
    let sse_c_algo = headers
        .get("x-amz-server-side-encryption-customer-algorithm")
        .and_then(|v| v.to_str().ok());
    let sse_c_key = headers
        .get("x-amz-server-side-encryption-customer-key")
        .and_then(|v| v.to_str().ok());
    let sse_c_key_md5 = headers
        .get("x-amz-server-side-encryption-customer-key-md5")
        .and_then(|v| v.to_str().ok());

    // Cannot mix SSE-S3 and SSE-C
    if sse_header.is_some() && sse_c_algo.is_some() {
        return Err(S3Error::InvalidArgument(
            "Cannot specify both x-amz-server-side-encryption and SSE-C headers.".to_string(),
        ));
    }

    // SSE-C
    if let Some(algo) = sse_c_algo {
        if algo != "AES256" {
            return Err(S3Error::InvalidEncryptionAlgorithmError);
        }
        let key_b64 = sse_c_key.ok_or(S3Error::MissingSecurityHeader)?;
        let key_md5_b64 = sse_c_key_md5.ok_or(S3Error::MissingSecurityHeader)?;

        let key_bytes = BASE64
            .decode(key_b64)
            .map_err(|_| S3Error::InvalidArgument("Invalid base64 in customer key.".to_string()))?;
        if key_bytes.len() != 32 {
            return Err(S3Error::InvalidArgument(
                "Customer key must be exactly 256 bits.".to_string(),
            ));
        }

        // Verify MD5
        let computed_md5 = md5::compute(&key_bytes);
        let expected_md5 = BASE64.encode(computed_md5.as_ref());
        if expected_md5 != key_md5_b64 {
            return Err(S3Error::InvalidArgument(
                "Customer key MD5 does not match.".to_string(),
            ));
        }

        let mut key = [0u8; 32];
        key.copy_from_slice(&key_bytes);
        return Ok(SseRequest::SseC {
            key,
            key_md5: key_md5_b64.to_string(),
        });
    }

    // SSE-S3
    if let Some(sse) = sse_header {
        if sse != "AES256" {
            return Err(S3Error::InvalidEncryptionAlgorithmError);
        }
        return Ok(SseRequest::SseS3);
    }

    Ok(SseRequest::None)
}

/// Parse SSE-C headers for a CopyObject source.
pub fn parse_sse_c_copy_source_headers(
    headers: &HeaderMap,
) -> Result<Option<SseCCopySource>, S3Error> {
    let algo = headers
        .get("x-amz-copy-source-server-side-encryption-customer-algorithm")
        .and_then(|v| v.to_str().ok());
    let key_b64 = headers
        .get("x-amz-copy-source-server-side-encryption-customer-key")
        .and_then(|v| v.to_str().ok());
    let key_md5_b64 = headers
        .get("x-amz-copy-source-server-side-encryption-customer-key-md5")
        .and_then(|v| v.to_str().ok());

    let algo = match algo {
        Some(a) => a,
        None => return Ok(None),
    };

    if algo != "AES256" {
        return Err(S3Error::InvalidEncryptionAlgorithmError);
    }
    let key_b64 = key_b64.ok_or(S3Error::MissingSecurityHeader)?;
    let key_md5_b64 = key_md5_b64.ok_or(S3Error::MissingSecurityHeader)?;

    let key_bytes = BASE64
        .decode(key_b64)
        .map_err(|_| S3Error::InvalidArgument("Invalid base64 in copy source key.".to_string()))?;
    if key_bytes.len() != 32 {
        return Err(S3Error::InvalidArgument(
            "Copy source key must be exactly 256 bits.".to_string(),
        ));
    }

    let computed_md5 = md5::compute(&key_bytes);
    let expected_md5 = BASE64.encode(computed_md5.as_ref());
    if expected_md5 != key_md5_b64 {
        return Err(S3Error::InvalidArgument(
            "Copy source key MD5 does not match.".to_string(),
        ));
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(&key_bytes);
    Ok(Some(SseCCopySource {
        key,
        key_md5: key_md5_b64.to_string(),
    }))
}

/// Parse SSE-C headers for GET/HEAD requests.
/// Returns the customer key and MD5 if SSE-C headers are present.
pub fn parse_sse_c_get_headers(headers: &HeaderMap) -> Result<Option<([u8; 32], String)>, S3Error> {
    let algo = headers
        .get("x-amz-server-side-encryption-customer-algorithm")
        .and_then(|v| v.to_str().ok());

    let algo = match algo {
        Some(a) => a,
        None => return Ok(None),
    };

    if algo != "AES256" {
        return Err(S3Error::InvalidEncryptionAlgorithmError);
    }

    let key_b64 = headers
        .get("x-amz-server-side-encryption-customer-key")
        .and_then(|v| v.to_str().ok())
        .ok_or(S3Error::MissingSecurityHeader)?;
    let key_md5_b64 = headers
        .get("x-amz-server-side-encryption-customer-key-md5")
        .and_then(|v| v.to_str().ok())
        .ok_or(S3Error::MissingSecurityHeader)?;

    let key_bytes = BASE64
        .decode(key_b64)
        .map_err(|_| S3Error::InvalidArgument("Invalid base64 in customer key.".to_string()))?;
    if key_bytes.len() != 32 {
        return Err(S3Error::InvalidArgument(
            "Customer key must be exactly 256 bits.".to_string(),
        ));
    }

    let computed_md5 = md5::compute(&key_bytes);
    let expected_md5 = BASE64.encode(computed_md5.as_ref());
    if expected_md5 != key_md5_b64 {
        return Err(S3Error::InvalidArgument(
            "Customer key MD5 does not match.".to_string(),
        ));
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(&key_bytes);
    Ok(Some((key, key_md5_b64.to_string())))
}

/// Derive a per-object encryption key from the master key using HKDF-SHA256.
pub fn derive_sse_s3_key(master_key: &[u8; 32], salt: &[u8; 32]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(salt), master_key);
    let mut okm = [0u8; 32];
    hk.expand(HKDF_INFO, &mut okm).expect("HKDF expand failed");
    okm
}

/// Generate random bytes of the given size.
fn rand_bytes<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    rand::rng().fill_bytes(&mut buf);
    buf
}

/// Compute the nonce for a specific chunk by XORing the base nonce with the chunk index.
fn chunk_nonce(base_nonce: &[u8; 12], chunk_index: u64) -> [u8; 12] {
    let mut nonce = *base_nonce;
    let idx_bytes = chunk_index.to_be_bytes();
    // XOR last 8 bytes of nonce with chunk index
    for i in 0..8 {
        nonce[4 + i] ^= idx_bytes[i];
    }
    nonce
}

/// Encrypt a single chunk using AES-256-GCM.
fn encrypt_chunk(
    cipher: &Aes256Gcm,
    base_nonce: &[u8; 12],
    chunk_index: u64,
    plaintext: &[u8],
) -> Result<Vec<u8>, S3Error> {
    let nonce_bytes = chunk_nonce(base_nonce, chunk_index);
    let nonce = Nonce::from_slice(&nonce_bytes);
    cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| S3Error::InternalError("Encryption failed.".to_string()))
}

/// Decrypt a single chunk using AES-256-GCM.
fn decrypt_chunk(
    cipher: &Aes256Gcm,
    base_nonce: &[u8; 12],
    chunk_index: u64,
    ciphertext: &[u8],
) -> Result<Vec<u8>, S3Error> {
    let nonce_bytes = chunk_nonce(base_nonce, chunk_index);
    let nonce = Nonce::from_slice(&nonce_bytes);
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| S3Error::AccessDenied)
}

/// Encrypt a file in place: read plaintext, write ciphertext to .tmp, then rename.
/// Returns the plaintext size.
pub async fn encrypt_file_in_place(
    path: &Path,
    key: &[u8; 32],
    base_nonce: &[u8; 12],
) -> Result<u64, S3Error> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| S3Error::InternalError("Invalid encryption key.".to_string()))?;

    let mut reader = tokio::fs::File::open(path)
        .await
        .map_err(|e| S3Error::InternalError(e.to_string()))?;

    let tmp_path = path.with_extension("enc.tmp");
    let mut writer = tokio::fs::File::create(&tmp_path)
        .await
        .map_err(|e| S3Error::InternalError(e.to_string()))?;

    let mut buf = vec![0u8; CHUNK_SIZE];
    let mut chunk_index: u64 = 0;
    let mut plaintext_size: u64 = 0;

    loop {
        let n = read_exact_or_eof(&mut reader, &mut buf).await?;
        if n == 0 {
            break;
        }
        plaintext_size += n as u64;
        let encrypted = encrypt_chunk(&cipher, base_nonce, chunk_index, &buf[..n])?;
        writer
            .write_all(&encrypted)
            .await
            .map_err(|e| S3Error::InternalError(e.to_string()))?;
        chunk_index += 1;
    }

    writer
        .flush()
        .await
        .map_err(|e| S3Error::InternalError(e.to_string()))?;
    drop(writer);

    tokio::fs::rename(&tmp_path, path)
        .await
        .map_err(|e| S3Error::InternalError(e.to_string()))?;

    Ok(plaintext_size)
}

/// Decrypt a file to a new plaintext file.
/// Used for CopyObject from an encrypted source.
pub async fn decrypt_file_to(
    src: &Path,
    dst: &Path,
    key: &[u8; 32],
    base_nonce: &[u8; 12],
    plaintext_size: u64,
) -> Result<(), S3Error> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| S3Error::InternalError("Invalid encryption key.".to_string()))?;

    let mut reader = tokio::fs::File::open(src)
        .await
        .map_err(|e| S3Error::InternalError(e.to_string()))?;

    let mut writer = tokio::fs::File::create(dst)
        .await
        .map_err(|e| S3Error::InternalError(e.to_string()))?;

    let encrypted_chunk_size = CHUNK_SIZE + TAG_SIZE;
    let mut buf = vec![0u8; encrypted_chunk_size];
    let mut chunk_index: u64 = 0;
    let mut remaining = plaintext_size;

    while remaining > 0 {
        let expected_plain = remaining.min(CHUNK_SIZE as u64) as usize;
        let expected_cipher = expected_plain + TAG_SIZE;
        let n = read_exact_or_eof(&mut reader, &mut buf[..expected_cipher]).await?;
        if n == 0 {
            break;
        }
        let plaintext = decrypt_chunk(&cipher, base_nonce, chunk_index, &buf[..n])?;
        writer
            .write_all(&plaintext)
            .await
            .map_err(|e| S3Error::InternalError(e.to_string()))?;
        remaining -= plaintext.len() as u64;
        chunk_index += 1;
    }

    writer
        .flush()
        .await
        .map_err(|e| S3Error::InternalError(e.to_string()))?;

    Ok(())
}

/// Build a decrypting HTTP response body that streams decrypted chunks.
/// Returns a `BoxBody` suitable for use in a hyper Response.
pub fn build_decrypting_body(
    file: tokio::fs::File,
    key: [u8; 32],
    base_nonce: [u8; 12],
    plaintext_size: u64,
) -> crate::handlers::BoxBody {
    use futures_util::stream::Stream;
    use http_body_util::StreamBody;
    use hyper::body::Frame;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::io::AsyncRead as _;

    struct DecryptStream {
        reader: tokio::fs::File,
        cipher: Aes256Gcm,
        base_nonce: [u8; 12],
        chunk_index: u64,
        remaining: u64,
        buf: Vec<u8>,
        done: bool,
    }

    impl Stream for DecryptStream {
        type Item = Result<Frame<bytes::Bytes>, std::io::Error>;

        fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            let this = self.get_mut();
            if this.done || this.remaining == 0 {
                return Poll::Ready(None);
            }

            let expected_plain = this.remaining.min(CHUNK_SIZE as u64) as usize;
            let expected_cipher = expected_plain + TAG_SIZE;

            // Ensure buffer is large enough
            if this.buf.len() < expected_cipher {
                this.buf.resize(expected_cipher, 0);
            }

            let buf = &mut this.buf[..expected_cipher];
            let mut read_buf = tokio::io::ReadBuf::new(buf);

            // We need to fill the buffer completely for this chunk
            loop {
                let filled_before = read_buf.filled().len();
                match Pin::new(&mut this.reader).poll_read(cx, &mut read_buf) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(e)) => return Poll::Ready(Some(Err(e))),
                    Poll::Ready(Ok(())) => {
                        let filled_now = read_buf.filled().len();
                        if filled_now == filled_before {
                            // EOF
                            this.done = true;
                            if filled_now == 0 {
                                return Poll::Ready(None);
                            }
                            break;
                        }
                        if filled_now >= expected_cipher {
                            break;
                        }
                        // Continue reading to fill the buffer
                    }
                }
            }

            let filled = read_buf.filled().len();
            match decrypt_chunk(
                &this.cipher,
                &this.base_nonce,
                this.chunk_index,
                &this.buf[..filled],
            ) {
                Ok(plaintext) => {
                    this.remaining -= plaintext.len() as u64;
                    this.chunk_index += 1;
                    Poll::Ready(Some(Ok(Frame::data(bytes::Bytes::from(plaintext)))))
                }
                Err(_) => {
                    this.done = true;
                    Poll::Ready(Some(Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Decryption failed",
                    ))))
                }
            }
        }
    }

    let cipher = Aes256Gcm::new_from_slice(&key).expect("valid key size");

    let stream = DecryptStream {
        reader: file,
        cipher,
        base_nonce,
        chunk_index: 0,
        remaining: plaintext_size,
        buf: vec![0u8; CHUNK_SIZE + TAG_SIZE],
        done: false,
    };

    use http_body_util::BodyExt;
    StreamBody::new(stream).boxed()
}

/// Encrypt an object at path using SSE-S3. Returns EncryptionMeta.
pub async fn encrypt_sse_s3(path: &Path, master_key: &[u8; 32]) -> Result<EncryptionMeta, S3Error> {
    let salt: [u8; 32] = rand_bytes();
    let nonce: [u8; 12] = rand_bytes();
    let dek = derive_sse_s3_key(master_key, &salt);

    let plaintext_size = encrypt_file_in_place(path, &dek, &nonce).await?;

    Ok(EncryptionMeta {
        algorithm: SseAlgorithm::SseS3,
        nonce: BASE64.encode(nonce),
        key_salt: Some(BASE64.encode(salt)),
        customer_key_md5: None,
        plaintext_size,
    })
}

/// Encrypt an object at path using SSE-C. Returns EncryptionMeta.
pub async fn encrypt_sse_c(
    path: &Path,
    customer_key: &[u8; 32],
    customer_key_md5: &str,
) -> Result<EncryptionMeta, S3Error> {
    let nonce: [u8; 12] = rand_bytes();

    let plaintext_size = encrypt_file_in_place(path, customer_key, &nonce).await?;

    Ok(EncryptionMeta {
        algorithm: SseAlgorithm::SseC,
        nonce: BASE64.encode(nonce),
        key_salt: None,
        customer_key_md5: Some(customer_key_md5.to_string()),
        plaintext_size,
    })
}

/// Resolve the decryption key for an encrypted object.
/// For SSE-S3, derives the key from the master key + stored salt.
/// For SSE-C, returns the customer key (caller must validate MD5 first).
pub fn resolve_decryption_key(
    enc_meta: &EncryptionMeta,
    encryption_config: Option<&EncryptionConfig>,
    customer_key: Option<&[u8; 32]>,
) -> Result<[u8; 32], S3Error> {
    match enc_meta.algorithm {
        SseAlgorithm::SseS3 => {
            let config = encryption_config
                .ok_or_else(|| S3Error::InternalError("Master key not configured.".to_string()))?;
            let salt_b64 = enc_meta
                .key_salt
                .as_ref()
                .ok_or_else(|| S3Error::InternalError("Missing key salt.".to_string()))?;
            let salt_bytes = BASE64
                .decode(salt_b64)
                .map_err(|_| S3Error::InternalError("Invalid salt encoding.".to_string()))?;
            let mut salt = [0u8; 32];
            if salt_bytes.len() != 32 {
                return Err(S3Error::InternalError("Invalid salt length.".to_string()));
            }
            salt.copy_from_slice(&salt_bytes);
            Ok(derive_sse_s3_key(&config.master_key, &salt))
        }
        SseAlgorithm::SseC => customer_key.copied().ok_or(S3Error::MissingSecurityHeader),
    }
}

/// Decode the base64 nonce from EncryptionMeta.
pub fn decode_nonce(enc_meta: &EncryptionMeta) -> Result<[u8; 12], S3Error> {
    let bytes = BASE64
        .decode(&enc_meta.nonce)
        .map_err(|_| S3Error::InternalError("Invalid nonce encoding.".to_string()))?;
    if bytes.len() != 12 {
        return Err(S3Error::InternalError("Invalid nonce length.".to_string()));
    }
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&bytes);
    Ok(nonce)
}

/// Read up to buf.len() bytes, retrying on short reads until EOF or full.
async fn read_exact_or_eof(reader: &mut tokio::fs::File, buf: &mut [u8]) -> Result<usize, S3Error> {
    let mut total = 0;
    while total < buf.len() {
        let n = reader
            .read(&mut buf[total..])
            .await
            .map_err(|e| S3Error::InternalError(e.to_string()))?;
        if n == 0 {
            break;
        }
        total += n;
    }
    Ok(total)
}
