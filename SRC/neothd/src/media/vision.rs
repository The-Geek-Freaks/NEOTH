//! Vision backend — R-9 Phase 2 + Phase 2b.
//!
//! Pure-Rust image decode via the `image` crate (PNG / JPEG / WebP /
//! GIF). Returns image dimensions + (when the operator has the CLIP
//! checkpoint cached locally) a 512-dim L2-normalised embedding so the
//! recall layer can do cosine-similarity search across images without
//! ever calling a cloud vision API.
//!
//! Phase 2b runtime split:
//!   1. Decode happens unconditionally (already shipped in Phase 2).
//!   2. The CLIP forward pass attempts only when the safetensors +
//!      config.json files are already on disk under
//!      `~/.neoth/models/openai-clip-vit-base-patch32/`.
//!      Cold first run = no embed; metadata says `model not cached`.
//!      Operator triggers the ~605 MiB download out-of-band (warm-up
//!      CLI, separate from media extract, deferred to ops-tooling
//!      Phase 2c).
//!   3. When the pass runs the embedding is L2-normalised and emitted
//!      under `metadata.embedding` (Vec<f32> length 512) so downstream
//!      consumers can persist it directly.
//!
//! What is NOT in scope today:
//!   - Local caption generation; no local vision-caption backend is offered.
//!   - GPU acceleration for CLIP — CPU forward stays portable.
//!   - Embedding-vector WAL events (0x2C+ band reserved); recall write
//!     happens via the extraction-side caller when it persists to
//!     SQLite.

use std::io::{Cursor, Read};

use super::{Asset, AssetKind, Extraction, ExtractionError, MediaExtractor};
use crate::providers::clip_engine;

/// Hard image-size ceiling — refuse anything past this to keep the WAL
/// payload bound consistent with the writer's MAX_PAYLOAD_BYTES.
const MAX_IMAGE_BYTES: usize = 16 * 1024 * 1024;
/// Dimension and decoded-allocation bounds are independent from compressed
/// size: a tiny PNG can otherwise expand into hundreds of millions of pixels.
const MAX_IMAGE_DIMENSION: u32 = 16_384;
const MAX_IMAGE_PIXELS: u64 = 40_000_000;
const MAX_IMAGE_DECODE_ALLOC_BYTES: u64 = 256 * 1024 * 1024;

pub struct VisionExtractor;

#[async_trait::async_trait]
impl MediaExtractor for VisionExtractor {
    fn name(&self) -> &'static str {
        "vision"
    }
    async fn extract(&self, asset: &Asset) -> Result<Extraction, ExtractionError> {
        if asset.kind() != AssetKind::Image {
            return Err(ExtractionError::Unsupported {
                backend: "vision",
                got: asset.kind(),
            });
        }
        let payload = asset.clone();
        tokio::task::spawn_blocking(move || extract_blocking(&payload))
            .await
            .map_err(|e| ExtractionError::Backend {
                backend: "vision",
                reason: format!("join error: {e}"),
            })?
    }
}

fn extract_blocking(asset: &Asset) -> Result<Extraction, ExtractionError> {
    let bytes = read_image_bytes(asset)?;

    let format = image::guess_format(&bytes).map_err(|e| ExtractionError::Backend {
        backend: "vision",
        reason: format!("guess_format: {e}"),
    })?;
    let img = decode_bounded(&bytes, format)?;
    let width = img.width();
    let height = img.height();
    validate_image_dimensions(width, height)?;
    // The dimensions/pixel budget is checked before this format-conversion
    // copy. `to_rgb8` can allocate three bytes per pixel in addition to the
    // decoder's native buffer.
    let rgb = img.to_rgb8();

    // Try the CLIP embedding pass. It is best-effort by design — a
    // cold install ships without the checkpoint and we surface that
    // honestly in metadata rather than blocking decode.
    let (embedding, embed_status) = embed_if_cached(&rgb);

    let mut metadata = serde_json::json!({
        "extractor": "vision",
        "format": format!("{format:?}").to_lowercase(),
        "width": width,
        "height": height,
        "pixel_count": (width as u64) * (height as u64),
        "rgb_byte_count": rgb.as_raw().len(),
        "embed_status": embed_status,
    });
    if let Some(vec) = embedding {
        metadata["embedding"] = serde_json::Value::Array(
            vec.into_iter()
                .map(|f| {
                    serde_json::Number::from_f64(f as f64)
                        .map(serde_json::Value::Number)
                        .unwrap_or(serde_json::Value::Null)
                })
                .collect(),
        );
        metadata["embed_dim"] = serde_json::json!(clip_engine::EMBED_DIM);
    }

    Ok(Extraction {
        text: String::new(),
        metadata,
    })
}

fn read_image_bytes(asset: &Asset) -> Result<Vec<u8>, ExtractionError> {
    match asset {
        Asset::Bytes { data, .. } => {
            enforce_image_byte_ceiling(data.len())?;
            Ok(data.clone())
        }
        Asset::Path { path, .. } => {
            let file = std::fs::File::open(path)
                .map_err(|e| ExtractionError::Io(format!("open {}: {e}", path.display())))?;
            let declared_len = file
                .metadata()
                .map_err(|e| ExtractionError::Io(format!("stat {}: {e}", path.display())))?
                .len();
            let declared_len =
                usize::try_from(declared_len).map_err(|_| ExtractionError::Backend {
                    backend: "vision",
                    reason: "image size does not fit this platform".into(),
                })?;
            enforce_image_byte_ceiling(declared_len)?;
            let mut bytes = Vec::with_capacity(declared_len);
            file.take(MAX_IMAGE_BYTES as u64 + 1)
                .read_to_end(&mut bytes)
                .map_err(|e| ExtractionError::Io(format!("read {}: {e}", path.display())))?;
            enforce_image_byte_ceiling(bytes.len())?;
            Ok(bytes)
        }
    }
}

fn enforce_image_byte_ceiling(len: usize) -> Result<(), ExtractionError> {
    if len > MAX_IMAGE_BYTES {
        return Err(ExtractionError::Backend {
            backend: "vision",
            reason: format!("image bytes {len} exceed {MAX_IMAGE_BYTES} ceiling"),
        });
    }
    Ok(())
}

fn decoder_limits() -> image::Limits {
    let mut limits = image::Limits::default();
    limits.max_image_width = Some(MAX_IMAGE_DIMENSION);
    limits.max_image_height = Some(MAX_IMAGE_DIMENSION);
    limits.max_alloc = Some(MAX_IMAGE_DECODE_ALLOC_BYTES);
    limits
}

fn decode_bounded(
    bytes: &[u8],
    format: image::ImageFormat,
) -> Result<image::DynamicImage, ExtractionError> {
    // Header-only dimension discovery avoids allocating the decoded image
    // before the aggregate pixel cap is known.
    let mut header_reader = image::ImageReader::with_format(Cursor::new(bytes), format);
    header_reader.limits(decoder_limits());
    let (width, height) =
        header_reader
            .into_dimensions()
            .map_err(|e| ExtractionError::Backend {
                backend: "vision",
                reason: format!("read dimensions: {e}"),
            })?;
    validate_image_dimensions(width, height)?;

    let mut reader = image::ImageReader::with_format(Cursor::new(bytes), format);
    reader.limits(decoder_limits());
    reader.decode().map_err(|e| ExtractionError::Backend {
        backend: "vision",
        reason: format!("decode: {e}"),
    })
}

fn validate_image_dimensions(width: u32, height: u32) -> Result<(), ExtractionError> {
    if width == 0 || height == 0 {
        return Err(ExtractionError::Backend {
            backend: "vision",
            reason: format!("image has invalid zero dimension {width}x{height}"),
        });
    }
    if width > MAX_IMAGE_DIMENSION || height > MAX_IMAGE_DIMENSION {
        return Err(ExtractionError::Backend {
            backend: "vision",
            reason: format!(
                "image dimensions {width}x{height} exceed the {MAX_IMAGE_DIMENSION}-pixel axis cap"
            ),
        });
    }
    let pixels = u64::from(width)
        .checked_mul(u64::from(height))
        .ok_or_else(|| ExtractionError::Backend {
            backend: "vision",
            reason: "image pixel-count overflow".into(),
        })?;
    if pixels > MAX_IMAGE_PIXELS {
        return Err(ExtractionError::Backend {
            backend: "vision",
            reason: format!(
                "image has {pixels} pixels, exceeding the {MAX_IMAGE_PIXELS}-pixel cap"
            ),
        });
    }
    Ok(())
}

/// Best-effort CLIP embedding. Returns `(Some(vec), "ok")` when the
/// model artifacts are cached and the forward pass succeeded, otherwise
/// a status string describing why no embedding was produced. We never
/// fail the extraction over a missing or broken CLIP install — decode
/// + dimensions are the contract; the embedding is a bonus.
fn embed_if_cached(rgb_image: &image::RgbImage) -> (Option<Vec<f32>>, &'static str) {
    let repo = clip_engine::DEFAULT_CLIP_REPO;
    let cache_dir = clip_engine::default_cache_dir(repo);
    for f in [clip_engine::CONFIG_FILE, clip_engine::SAFETENSORS_FILE] {
        if !cache_dir.join(f).exists() {
            return (None, "model not cached");
        }
    }
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(_) => return (None, "runtime init failed"),
    };
    let result = runtime.block_on(async {
        let engine = clip_engine::ClipEngine::new(Some(repo.to_string())).await?;
        engine
            .embed_image(rgb_image.as_raw(), rgb_image.width(), rgb_image.height())
            .await
    });
    match result {
        Ok(v) => (Some(v), "ok"),
        Err(e) => {
            tracing::warn!(error = %e, "CLIP forward pass failed");
            (None, "embed failed")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a 4×4 red PNG in memory so we can exercise the decode path
    /// without shipping a binary fixture.
    fn synth_red_png() -> Vec<u8> {
        let mut img = image::RgbImage::new(4, 4);
        for pixel in img.pixels_mut() {
            *pixel = image::Rgb([255, 0, 0]);
        }
        let mut buf = Vec::new();
        let dyn_img = image::DynamicImage::ImageRgb8(img);
        dyn_img
            .write_to(&mut std::io::Cursor::new(&mut buf), image::ImageFormat::Png)
            .expect("encode png");
        buf
    }

    #[tokio::test]
    async fn extract_returns_unsupported_for_non_image() {
        let extractor = VisionExtractor;
        let asset = Asset::Bytes {
            kind: AssetKind::Pdf,
            mime: "application/pdf".into(),
            data: b"%PDF".to_vec(),
        };
        let err = extractor.extract(&asset).await.unwrap_err();
        assert!(matches!(
            err,
            ExtractionError::Unsupported {
                backend: "vision",
                ..
            }
        ));
    }

    #[tokio::test]
    async fn extract_decodes_png_and_reports_dimensions() {
        let extractor = VisionExtractor;
        let asset = Asset::Bytes {
            kind: AssetKind::Image,
            mime: "image/png".into(),
            data: synth_red_png(),
        };
        let out = extractor.extract(&asset).await.expect("decode png");
        assert!(out.text.is_empty(), "caption deferred to Phase 2c");
        assert_eq!(out.metadata["width"], 4);
        assert_eq!(out.metadata["height"], 4);
        assert_eq!(out.metadata["pixel_count"], 16);
        assert_eq!(out.metadata["rgb_byte_count"], 48); // 16 px × 3 channels
        // embed_status is always present; "ok" when the operator has the
        // CLIP checkpoint cached, "model not cached" otherwise. Either
        // is valid for this test — we just require the field exists so
        // future readers know whether to trust metadata.embedding.
        let status = out.metadata["embed_status"]
            .as_str()
            .expect("embed_status string");
        assert!(
            matches!(status, "ok" | "model not cached" | "embed failed"),
            "unexpected embed_status: {status}"
        );
    }

    #[tokio::test]
    async fn extract_rejects_oversize_payload() {
        let extractor = VisionExtractor;
        let big = vec![0u8; MAX_IMAGE_BYTES + 1];
        let asset = Asset::Bytes {
            kind: AssetKind::Image,
            mime: "image/png".into(),
            data: big,
        };
        let err = extractor.extract(&asset).await.unwrap_err();
        let matched = matches!(
            &err,
            ExtractionError::Backend { backend: "vision", reason } if reason.contains("ceiling"),
        );
        assert!(matched, "got: {err:?}");
    }

    #[test]
    fn compressed_image_cannot_bypass_dimension_or_pixel_caps() {
        assert!(validate_image_dimensions(10_000, 4_000).is_ok());
        let pixels = validate_image_dimensions(10_001, 4_000).unwrap_err();
        assert!(
            matches!(
                pixels,
                ExtractionError::Backend {
                    backend: "vision",
                    ref reason
                } if reason.contains("pixel cap")
            ),
            "{pixels:?}"
        );

        let axis = validate_image_dimensions(MAX_IMAGE_DIMENSION + 1, 1).unwrap_err();
        assert!(
            matches!(
                axis,
                ExtractionError::Backend {
                    backend: "vision",
                    ref reason
                } if reason.contains("axis cap")
            ),
            "{axis:?}"
        );
        assert!(validate_image_dimensions(0, 1).is_err());
    }

    #[test]
    fn image_decoder_receives_explicit_allocation_limits() {
        let limits = decoder_limits();
        assert_eq!(limits.max_image_width, Some(MAX_IMAGE_DIMENSION));
        assert_eq!(limits.max_image_height, Some(MAX_IMAGE_DIMENSION));
        assert_eq!(limits.max_alloc, Some(MAX_IMAGE_DECODE_ALLOC_BYTES));
    }

    #[tokio::test]
    async fn extract_errors_cleanly_on_garbage_bytes() {
        let extractor = VisionExtractor;
        let asset = Asset::Bytes {
            kind: AssetKind::Image,
            mime: "image/png".into(),
            data: b"not actually a png".to_vec(),
        };
        let err = extractor.extract(&asset).await.unwrap_err();
        assert!(matches!(
            err,
            ExtractionError::Backend {
                backend: "vision",
                ..
            }
        ));
    }
}
