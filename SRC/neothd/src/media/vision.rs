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

use super::{Asset, AssetKind, Extraction, ExtractionError, MediaExtractor};
use crate::providers::clip_engine;

/// Hard image-size ceiling — refuse anything past this to keep the WAL
/// payload bound consistent with the writer's MAX_PAYLOAD_BYTES.
const MAX_IMAGE_BYTES: usize = 16 * 1024 * 1024;

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
    let bytes = match asset {
        Asset::Bytes { data, .. } => {
            if data.len() > MAX_IMAGE_BYTES {
                return Err(ExtractionError::Backend {
                    backend: "vision",
                    reason: format!(
                        "image bytes {} exceed {} ceiling",
                        data.len(),
                        MAX_IMAGE_BYTES
                    ),
                });
            }
            data.clone()
        }
        Asset::Path { path, .. } => std::fs::read(path)
            .map_err(|e| ExtractionError::Io(format!("read {}: {e}", path.display())))?,
    };

    let format = image::guess_format(&bytes).map_err(|e| ExtractionError::Backend {
        backend: "vision",
        reason: format!("guess_format: {e}"),
    })?;
    let img = image::load_from_memory(&bytes).map_err(|e| ExtractionError::Backend {
        backend: "vision",
        reason: format!("decode: {e}"),
    })?;
    let rgb = img.to_rgb8();
    let width = rgb.width();
    let height = rgb.height();

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
