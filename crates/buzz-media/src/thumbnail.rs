//! Synchronous thumbnail generation and blurhash encoding.

use std::io::Cursor;

use image::ImageFormat;

use crate::config::MediaConfig;
use crate::error::MediaError;
use crate::storage::BlobMeta;
use crate::validation::MAX_IMAGE_DECODE_BYTES;

/// Generate thumbnail and blurhash from image bytes (CPU-bound, sync).
///
/// Returns `(metadata, optional thumbnail JPEG bytes)`.
/// Caller handles S3 writes after `spawn_blocking` returns.
pub fn generate_image_metadata_sync(
    config: &MediaConfig,
    sha256: &str,
    bytes: &[u8],
    mime: &str,
    ext: &str,
) -> Result<(BlobMeta, Option<Vec<u8>>), MediaError> {
    if !mime.starts_with("image/") {
        return Ok((BlobMeta::default(), None));
    }

    // The pixel gate in `validate_content` already bounds the picture at
    // `MAX_IMAGE_PIXELS`; decode under the allocation that cap implies rather
    // than the image crate's default (512 MiB), which would reject a 16-bit
    // image the gate accepted.
    let mut limits = image::Limits::no_limits();
    limits.max_alloc = Some(MAX_IMAGE_DECODE_BYTES);
    let mut reader = image::ImageReader::new(Cursor::new(bytes))
        .with_guessed_format()
        .map_err(|e| MediaError::Io(e.to_string()))?;
    reader.limits(limits);
    let img = reader.decode()?;
    let (w, h) = (img.width(), img.height());

    // Thumbnail: 320px max dimension, preserve aspect ratio
    let thumb = img.thumbnail(320, 320);
    let mut thumb_bytes = Vec::new();
    thumb.write_to(&mut Cursor::new(&mut thumb_bytes), ImageFormat::Jpeg)?;

    // Blurhash from thumbnail (faster than full image)
    let rgba = thumb.to_rgba8();
    let bh =
        blurhash::encode(4, 3, thumb.width(), thumb.height(), rgba.as_raw()).unwrap_or_default();

    Ok((
        BlobMeta {
            dim: format!("{w}x{h}"),
            blurhash: bh,
            thumb_url: format!("{}/{sha256}.thumb.jpg", config.public_base_url),
            ext: ext.to_string(),
            mime_type: mime.to_string(),
            size: bytes.len() as u64,
            ..BlobMeta::default() // uploaded_at set by caller (process_upload)
        },
        Some(thumb_bytes),
    ))
}
