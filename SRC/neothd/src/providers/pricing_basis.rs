//! Exact, content-free price provenance for terminal usage records.
//!
//! This describes NEOTH's static estimate, not a provider invoice or a new
//! charge. Historical records validate their own basis without today's table.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::cost::PriceRow;

const ALGORITHM: &str = "neoth.provider-cost.v1";
pub(super) const EUR_PER_USD: f64 = 0.92;
pub(super) const CACHE_CREATE_MULTIPLIER: f64 = 1.25;
pub(super) const CACHE_READ_MULTIPLIER: f64 = 0.10;
pub(super) const CACHE_READ_SAVINGS: f64 = 0.90;
pub(super) const CACHE_CREATE_PREMIUM: f64 = 0.25;

/// Immutable version of the effective row and calculation constants. Bit
/// strings preserve the original f32 rates without decimal round-trip loss.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PricingBasis {
    pub algorithm: String,
    pub provider: String,
    pub model: String,
    pub input_eur_per_mtok_bits: String,
    pub output_eur_per_mtok_bits: String,
    pub fx_eur_per_usd_bits: String,
    pub cache_create_multiplier_bits: String,
    pub cache_read_multiplier_bits: String,
    pub cache_read_savings_bits: String,
    pub cache_create_premium_bits: String,
    pub basis_id: String,
}

impl PricingBasis {
    pub(crate) fn from_price(provider: &str, model: &str, price: PriceRow) -> Self {
        let mut basis = Self {
            algorithm: ALGORITHM.to_owned(),
            provider: provider.to_owned(),
            model: model.to_owned(),
            input_eur_per_mtok_bits: format!("{:08x}", price.input_eur_per_mtok.to_bits()),
            output_eur_per_mtok_bits: format!("{:08x}", price.output_eur_per_mtok.to_bits()),
            fx_eur_per_usd_bits: format!("{:016x}", EUR_PER_USD.to_bits()),
            cache_create_multiplier_bits: format!("{:016x}", CACHE_CREATE_MULTIPLIER.to_bits()),
            cache_read_multiplier_bits: format!("{:016x}", CACHE_READ_MULTIPLIER.to_bits()),
            cache_read_savings_bits: format!("{:016x}", CACHE_READ_SAVINGS.to_bits()),
            cache_create_premium_bits: format!("{:016x}", CACHE_CREATE_PREMIUM.to_bits()),
            basis_id: String::new(),
        };
        basis.basis_id = basis.digest();
        basis
    }

    fn digest(&self) -> String {
        let mut digest = Sha256::new();
        for field in [
            "neoth.pricing-basis.v1",
            self.algorithm.as_str(),
            self.provider.as_str(),
            self.model.as_str(),
            self.input_eur_per_mtok_bits.as_str(),
            self.output_eur_per_mtok_bits.as_str(),
            self.fx_eur_per_usd_bits.as_str(),
            self.cache_create_multiplier_bits.as_str(),
            self.cache_read_multiplier_bits.as_str(),
            self.cache_read_savings_bits.as_str(),
            self.cache_create_premium_bits.as_str(),
        ] {
            digest.update((field.len() as u64).to_be_bytes());
            digest.update(field.as_bytes());
        }
        format!("{:x}", digest.finalize())
    }

    /// Validate frozen metadata, never consult current provider/model prices.
    pub(crate) fn validate(&self, provider: &str, model: &str) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.algorithm == ALGORITHM && self.provider == provider && self.model == model,
            "pricing basis identity or algorithm mismatch"
        );
        for bits in [
            &self.input_eur_per_mtok_bits,
            &self.output_eur_per_mtok_bits,
        ] {
            anyhow::ensure!(canonical_hex(bits, 8), "noncanonical pricing rate bits");
            let rate = f32::from_bits(u32::from_str_radix(bits, 16)?);
            anyhow::ensure!(
                rate.is_finite() && !rate.is_sign_negative(),
                "invalid pricing rate"
            );
        }
        // These constants define algorithm v1. A future calculation policy
        // needs a new algorithm version; historical v1 remains readable.
        for (bits, expected) in [
            (&self.fx_eur_per_usd_bits, EUR_PER_USD),
            (&self.cache_create_multiplier_bits, CACHE_CREATE_MULTIPLIER),
            (&self.cache_read_multiplier_bits, CACHE_READ_MULTIPLIER),
            (&self.cache_read_savings_bits, CACHE_READ_SAVINGS),
            (&self.cache_create_premium_bits, CACHE_CREATE_PREMIUM),
        ] {
            anyhow::ensure!(
                canonical_hex(bits, 16) && *bits == format!("{:016x}", expected.to_bits()),
                "pricing basis constants disagree with algorithm v1"
            );
        }
        anyhow::ensure!(
            self.basis_id == self.digest(),
            "pricing basis digest mismatch"
        );
        Ok(())
    }
}

fn canonical_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn price_basis_roundtrip_preserves_exact_row_and_policy() {
        let price = PriceRow {
            input_eur_per_mtok: 2.76,
            output_eur_per_mtok: 13.8,
        };
        let basis = PricingBasis::from_price("anthropic_api", "claude-sonnet-4-6", price);
        let restored: PricingBasis =
            serde_json::from_str(&serde_json::to_string(&basis).unwrap()).unwrap();
        assert_eq!(basis, restored);
        assert_eq!(
            basis.input_eur_per_mtok_bits,
            format!("{:08x}", price.input_eur_per_mtok.to_bits())
        );
        restored
            .validate("anthropic_api", "claude-sonnet-4-6")
            .unwrap();
        let changed = PricingBasis::from_price(
            "anthropic_api",
            "claude-sonnet-4-6",
            PriceRow {
                input_eur_per_mtok: 3.0,
                ..price
            },
        );
        assert_ne!(basis.basis_id, changed.basis_id);
    }

    #[test]
    fn price_basis_rejects_tampered_rates_policy_and_identity() {
        let basis = PricingBasis::from_price(
            "provider",
            "model",
            PriceRow {
                input_eur_per_mtok: 1.0,
                output_eur_per_mtok: 2.0,
            },
        );
        for field in [
            "input_eur_per_mtok_bits",
            "output_eur_per_mtok_bits",
            "fx_eur_per_usd_bits",
            "cache_create_multiplier_bits",
            "cache_read_multiplier_bits",
            "cache_read_savings_bits",
            "cache_create_premium_bits",
            "provider",
            "model",
            "algorithm",
            "basis_id",
        ] {
            let mut value = serde_json::to_value(&basis).unwrap();
            value[field] = "changed".into();
            let changed: PricingBasis = serde_json::from_value(value).unwrap();
            assert!(changed.validate("provider", "model").is_err(), "{field}");
        }
        assert!(basis.validate("other", "model").is_err());
        assert!(basis.validate("provider", "other").is_err());
    }

    #[test]
    fn price_basis_rejects_invalid_rates_even_with_matching_digest() {
        let basis = PricingBasis::from_price(
            "provider",
            "model",
            PriceRow {
                input_eur_per_mtok: 1.0,
                output_eur_per_mtok: 2.0,
            },
        );
        for bits in [
            "7fc00000", "7f800000", "bf800000", "80000000", "3F800000", "1",
        ] {
            let mut changed = basis.clone();
            changed.input_eur_per_mtok_bits = bits.to_owned();
            changed.basis_id = changed.digest();
            assert!(changed.validate("provider", "model").is_err(), "{bits}");
        }
        let mut changed = basis;
        changed.cache_read_multiplier_bits = format!("{:016x}", 0.5_f64.to_bits());
        changed.basis_id = changed.digest();
        assert!(changed.validate("provider", "model").is_err());
    }
}
