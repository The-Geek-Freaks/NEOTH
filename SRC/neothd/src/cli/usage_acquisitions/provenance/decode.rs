use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;

use super::super::collector::identity_ok;
use super::unique_json::parse_unique_json;
use crate::daemon::usage_log::{UsageEvent, retained_terminal_usage};
use crate::providers::pricing_basis::AuthorizationPriceBound;
use crate::wal::events::{EVENT_TYPE_PROVIDER_ERROR, EVENT_TYPE_PROVIDER_RESPONSE};

#[derive(Clone, Debug, Serialize, PartialEq)]
pub(super) struct Plan {
    pub invocation_id: String,
    pub binding: String,
    pub provider: String,
    pub wire_model: String,
    pub ts_unix: u64,
    pub input_upper_bound: u32,
    pub output_ceiling: Option<u32>,
    pub bound: Option<AuthorizationPriceBound>,
}

#[derive(Clone, Debug, Serialize, PartialEq)]
pub(super) struct Terminal {
    pub invocation_id: String,
    pub binding: Option<String>,
    pub lifecycle_bound: bool,
    pub provider: String,
    pub wire_model: String,
    pub ts_unix: u64,
    pub event_type: u8,
    pub projection_schema: String,
    pub amount_provenance: &'static str,
    pub cost_usd_bits: Option<String>,
    pub cache_savings_usd_bits: Option<String>,
    pub event: UsageEvent,
}

fn required_option<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

#[derive(Deserialize)]
struct PlanWire {
    invocation_id: String,
    authorization_binding: String,
    authorization_id: String,
    request_binding_sha256: String,
    provider: String,
    model: String,
    ts_unix: u64,
    input_token_upper_bound: u32,
    #[serde(deserialize_with = "required_option")]
    output_token_ceiling: Option<u32>,
    #[serde(deserialize_with = "required_option")]
    authorization_price_bound: Option<AuthorizationPriceBound>,
    cost_bound_kind: String,
    input_bound_kind: String,
}

pub(super) fn plan(payload: &[u8]) -> Result<Plan, &'static str> {
    let value = parse_unique_json(payload)?;
    let object = value.as_object().ok_or("malformed")?;
    if !object.contains_key("authorization_price_bound") {
        return Err("legacy_plan_unavailable");
    }
    let wire: PlanWire = serde_json::from_value(value).map_err(|_| "malformed")?;
    if !matches!(
        wire.cost_bound_kind.as_str(),
        "wire_token_bounded_reviewed_price_estimate"
            | "token_bounded_unknown_pricing"
            | "unbounded_provider_invocation"
    ) {
        return Err("unsupported_schema");
    }
    if wire.authorization_binding != "actual_leaf_request"
        || wire.authorization_id != wire.invocation_id
        || wire.input_bound_kind != "utf8_bytes_plus_request_message_overhead"
        || !identity_ok(
            &wire.invocation_id,
            &wire.request_binding_sha256,
            &wire.provider,
            &wire.model,
        )
        || wire.output_token_ceiling == Some(0)
    {
        return Err("malformed");
    }
    match (&wire.authorization_price_bound, wire.output_token_ceiling) {
        (Some(bound), Some(ceiling))
            if wire.cost_bound_kind == "wire_token_bounded_reviewed_price_estimate"
                && bound.input_upper_bound == wire.input_token_upper_bound
                && bound.output_ceiling == ceiling =>
        {
            bound
                .bound_usd(&wire.provider, &wire.model)
                .map_err(|_| "malformed")?;
        }
        (None, Some(_)) if wire.cost_bound_kind == "token_bounded_unknown_pricing" => {}
        (None, None) if wire.cost_bound_kind == "unbounded_provider_invocation" => {}
        _ => return Err("malformed"),
    }
    Ok(Plan {
        invocation_id: wire.invocation_id,
        binding: wire.request_binding_sha256,
        provider: wire.provider,
        wire_model: wire.model,
        ts_unix: wire.ts_unix,
        input_upper_bound: wire.input_token_upper_bound,
        output_ceiling: wire.output_token_ceiling,
        bound: wire.authorization_price_bound,
    })
}

fn required_string<'a>(
    object: &'a serde_json::Map<String, Value>,
    key: &str,
) -> Result<&'a str, &'static str> {
    object.get(key).and_then(Value::as_str).ok_or("malformed")
}

pub(super) fn terminal(event_type: u8, payload: &[u8]) -> Result<Terminal, &'static str> {
    let value = parse_unique_json(payload)?;
    let object = value.as_object().ok_or("malformed")?;
    let projection_schema = match object.get("usage_projection_schema") {
        None => return Err("legacy_usage_unavailable"),
        Some(Value::String(schema)) => schema.as_str(),
        Some(_) => return Err("malformed"),
    };
    let amount_provenance = match projection_schema {
        "neoth.provider-usage.v2" => "legacy_unpriced",
        "neoth.provider-usage.v3" | "neoth.provider-usage.v4" | "neoth.provider-usage.v5" => {
            "frozen_computed_amounts_not_invoice"
        }
        _ => return Err("unsupported_schema"),
    };
    let lifecycle_present = match object.get("schema") {
        None => false,
        Some(Value::String(schema)) if schema == "neoth.provider-lifecycle.v1" => true,
        Some(Value::String(_)) => return Err("unsupported_schema"),
        Some(_) => return Err("malformed"),
    };
    let invocation_id = required_string(object, "invocation_id")?;
    let provider = required_string(object, "provider")?;
    let ts_unix = object
        .get("ts_unix")
        .and_then(Value::as_u64)
        .ok_or("malformed")?;
    let model_field = |key: &str| -> Result<Option<&str>, &'static str> {
        match object.get(key) {
            None => Ok(None),
            Some(Value::String(s)) if !s.is_empty() => Ok(Some(s)),
            Some(_) => Err("malformed"),
        }
    };
    let wire_model = model_field("wire_model")?;
    let compat_model = model_field("model")?;
    if let (Some(a), Some(b)) = (wire_model, compat_model)
        && a != b
    {
        return Err("malformed");
    }
    let model = wire_model.or(compat_model).ok_or("malformed")?;
    let binding = match object.get("request_binding_sha256") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) => Some(s.as_str()),
        Some(_) => return Err("malformed"),
    };
    // Only the identity check uses this sentinel; absent bindings remain absent.
    let identity_binding =
        binding.unwrap_or("0000000000000000000000000000000000000000000000000000000000000000");
    if !identity_ok(invocation_id, identity_binding, provider, model) {
        return Err("malformed");
    }
    let event = retained_terminal_usage(payload)
        .map_err(|_| "malformed")?
        .ok_or("malformed")?;
    if event.provider != provider
        || event.model != model
        || event.invocation_id.as_deref() != Some(invocation_id)
        || u64::try_from(event.ts_unix).ok() != Some(ts_unix)
        || (event.ok && event_type != EVENT_TYPE_PROVIDER_RESPONSE)
        || (!event.ok && event_type != EVENT_TYPE_PROVIDER_ERROR)
    {
        return Err("malformed");
    }
    Ok(Terminal {
        invocation_id: invocation_id.to_owned(),
        binding: binding.map(str::to_owned),
        lifecycle_bound: lifecycle_present && binding.is_some(),
        provider: provider.to_owned(),
        wire_model: model.to_owned(),
        ts_unix,
        event_type,
        projection_schema: projection_schema.to_owned(),
        amount_provenance,
        cost_usd_bits: event
            .cost_usd
            .map(|value| format!("{:016x}", value.to_bits())),
        cache_savings_usd_bits: event
            .cache_savings_usd
            .map(|value| format!("{:016x}", value.to_bits())),
        event,
    })
}
