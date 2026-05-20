//! AWS credential chain for the Bedrock adapter (C-3 Phase 2, Session 14).
//!
//! NEOTH supports a deliberately small, closed-enum credential chain. The
//! AWS SDK's default chain has 8+ sources including `credential_process`
//! (executes arbitrary shell command on refresh — RCE-surface), ECS
//! container creds, IMDSv2, etc. The security-auditor review (Session 14
//! 4-agent consensus) ranked uncontrolled chain delegation as the
//! single highest-severity risk for this adapter.
//!
//! Supported sources, in priority order:
//!
//!   1. **`FreedomYaml`** — explicit `access_key_id` / `secret_access_key` /
//!      `session_token` passed in by the caller. Used when the operator
//!      pins credentials in their NEOTH config files (`HemisphereSlot.key`
//!      with embedded `id:secret` pair OR future per-slot credential
//!      fields).
//!   2. **`EnvVars`** — `AWS_ACCESS_KEY_ID` + `AWS_SECRET_ACCESS_KEY` from
//!      the process environment. `AWS_SESSION_TOKEN` is optional.
//!   3. **`SharedCredentialsFile`** — `[default]` profile in
//!      `~/.aws/credentials` (Windows: `%USERPROFILE%\.aws\credentials`).
//!      Only the `[default]` profile is read — multi-profile selection
//!      is out-of-scope for Phase 2 (operator can `AWS_PROFILE=foo` and
//!      use env-var path, or pin the keys directly in NEOTH config).
//!
//! Explicitly NOT supported (security-auditor guardrail #1):
//!
//!   - `credential_process` — shell-exec on refresh, RCE-surface
//!   - ECS / EKS task metadata — server scenarios out-of-scope
//!   - IMDSv2 — desktop NEOTH is never EC2
//!   - SSO / IAM Identity Center — token-refresh lifecycle complexity
//!   - `STS:AssumeRole` — multi-account chain depth out-of-scope
//!
//! The closed enum [`CredentialSource`] documents what NEOTH actually
//! reads from. Future additions land as new variants — never as
//! pass-through to the SDK.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::secret::SecretString;

/// Resolved AWS credentials handed to the SigV4 signer. Each field is
/// `SecretString`-typed so memory lock + zeroize-on-drop apply identical
/// to every other secret in NEOTH.
#[derive(Clone)]
pub struct AwsCredentials {
    pub access_key_id: SecretString,
    pub secret_access_key: SecretString,
    pub session_token: Option<SecretString>,
}

impl std::fmt::Debug for AwsCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AwsCredentials")
            .field("access_key_id", &"[REDACTED]")
            .field("secret_access_key", &"[REDACTED]")
            .field(
                "session_token",
                &self.session_token.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

/// Explicit enumeration of the credential sources NEOTH supports. Every
/// resolved [`AwsCredentials`] carries the source it came from so the
/// caller can surface this in error messages, telemetry, or operator
/// prompts ("loaded creds from env vars — set AWS_PROFILE=… to switch").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CredentialSource {
    /// Explicit fields in NEOTH's own config files.
    FreedomYaml,
    /// Process environment variables.
    EnvVars,
    /// `[default]` profile in `~/.aws/credentials`.
    SharedCredentialsFile,
}

/// Resolved-pair returned by [`resolve_chain`]. Carries the source so
/// the caller can log / surface origin to the operator without
/// re-deriving it.
#[derive(Debug)]
pub struct ResolvedCredentials {
    pub credentials: AwsCredentials,
    pub source: CredentialSource,
}

/// Walk the closed credential chain. Inputs:
///   - `freedom_yaml_creds`: caller-provided explicit credentials
///      (typically extracted from `HemisphereSlot.key` or future
///      per-slot fields). When `Some`, used immediately.
///   - `env`: getter for environment variables. Tests inject a
///      deterministic map; production callers pass [`env_var_getter`].
///   - `home_dir`: optional override for the user-home root used to
///      locate `~/.aws/credentials`. None → resolve via [`user_home`].
///
/// Returns an error with an actionable hint when no source yields a
/// complete `(access_key_id, secret_access_key)` pair.
pub fn resolve_chain(
    freedom_yaml_creds: Option<AwsCredentials>,
    env: &dyn Fn(&str) -> Option<String>,
    home_dir: Option<&Path>,
) -> Result<ResolvedCredentials> {
    if let Some(creds) = freedom_yaml_creds {
        return Ok(ResolvedCredentials {
            credentials: creds,
            source: CredentialSource::FreedomYaml,
        });
    }

    if let Some(env_creds) = from_env(env) {
        return Ok(ResolvedCredentials {
            credentials: env_creds,
            source: CredentialSource::EnvVars,
        });
    }

    let home = match home_dir {
        Some(p) => p.to_path_buf(),
        None => user_home(env)?,
    };
    if let Some(file_creds) = from_shared_file(&home)? {
        return Ok(ResolvedCredentials {
            credentials: file_creds,
            source: CredentialSource::SharedCredentialsFile,
        });
    }

    anyhow::bail!(
        "aws_bedrock: no credentials found in any supported source. \
         Configure ONE of: \
         (1) explicit `access_key_id` + `secret_access_key` in freedom.yaml under the aws_bedrock slot, \
         (2) AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY env vars (AWS_SESSION_TOKEN optional), \
         (3) `[default]` profile in ~/.aws/credentials. \
         NEOTH deliberately does NOT support `credential_process`, IMDSv2, ECS metadata, or SSO — \
         out-of-scope for the solo-operator threat model."
    )
}

/// Standard process-environment getter — production entry point. Tests
/// use a closure over a `HashMap` to keep them deterministic.
pub fn env_var_getter(name: &str) -> Option<String> {
    std::env::var(name).ok()
}

fn from_env(env: &dyn Fn(&str) -> Option<String>) -> Option<AwsCredentials> {
    let id = env("AWS_ACCESS_KEY_ID").filter(|s| !s.is_empty())?;
    let secret = env("AWS_SECRET_ACCESS_KEY").filter(|s| !s.is_empty())?;
    let token = env("AWS_SESSION_TOKEN").filter(|s| !s.is_empty());
    Some(AwsCredentials {
        access_key_id: SecretString::new(id),
        secret_access_key: SecretString::new(secret),
        session_token: token.map(SecretString::new),
    })
}

fn user_home(env: &dyn Fn(&str) -> Option<String>) -> Result<PathBuf> {
    // Windows: %USERPROFILE%, fallback %HOME%. Unix: $HOME.
    if let Some(p) = env("USERPROFILE").filter(|s| !s.is_empty()) {
        return Ok(PathBuf::from(p));
    }
    if let Some(p) = env("HOME").filter(|s| !s.is_empty()) {
        return Ok(PathBuf::from(p));
    }
    anyhow::bail!(
        "aws_bedrock: cannot locate user home directory — neither USERPROFILE nor HOME is set"
    )
}

fn from_shared_file(home: &Path) -> Result<Option<AwsCredentials>> {
    let path = home.join(".aws").join("credentials");
    if !path.exists() {
        return Ok(None);
    }
    let contents = std::fs::read_to_string(&path)
        .with_context(|| format!("read AWS shared credentials at {}", path.display()))?;
    Ok(parse_shared_credentials_default(&contents))
}

/// Parse only the `[default]` profile from a shared-credentials INI body.
/// Returns `None` when the profile is absent or incomplete. Multi-profile
/// support is intentionally out of scope (see module-level docs).
///
/// INI grammar tolerated:
///   - Lines starting with `#` or `;` are comments
///   - Blank lines ignored
///   - `[section]` headers (only `[default]` consulted)
///   - `key = value` pairs, whitespace-trimmed on both sides
///
/// Keys recognised inside `[default]`:
///   - `aws_access_key_id`
///   - `aws_secret_access_key`
///   - `aws_session_token` (optional)
///
/// Any `credential_process` key inside `[default]` is **ignored** —
/// security-auditor guardrail #1 (RCE surface).
pub fn parse_shared_credentials_default(body: &str) -> Option<AwsCredentials> {
    let mut in_default = false;
    let mut id: Option<String> = None;
    let mut secret: Option<String> = None;
    let mut token: Option<String> = None;

    for raw_line in body.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some(section) = line.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            in_default = section.trim().eq_ignore_ascii_case("default");
            continue;
        }
        if !in_default {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        let key = k.trim().to_ascii_lowercase();
        let value = v.trim().to_string();
        match key.as_str() {
            "aws_access_key_id" => id = Some(value),
            "aws_secret_access_key" => secret = Some(value),
            "aws_session_token" => token = Some(value),
            // Deliberately ignored — see security-auditor guardrail #1
            "credential_process" => {
                tracing::warn!(
                    "ignored `credential_process` in ~/.aws/credentials [default] — \
                     NEOTH does not exec shell commands for credential refresh"
                );
            }
            _ => {}
        }
    }

    match (id, secret) {
        (Some(id), Some(secret)) if !id.is_empty() && !secret.is_empty() => Some(AwsCredentials {
            access_key_id: SecretString::new(id),
            secret_access_key: SecretString::new(secret),
            session_token: token.filter(|s| !s.is_empty()).map(SecretString::new),
        }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn env_from(map: HashMap<&'static str, &'static str>) -> impl Fn(&str) -> Option<String> {
        move |k: &str| map.get(k).map(|v| v.to_string())
    }

    #[test]
    fn freedom_yaml_creds_short_circuit_chain() {
        let yaml_creds = AwsCredentials {
            access_key_id: SecretString::new("AKIA-explicit".into()),
            secret_access_key: SecretString::new("secret-explicit".into()),
            session_token: None,
        };
        // env has different keys — must NOT be consulted.
        let env = env_from(HashMap::from([
            ("AWS_ACCESS_KEY_ID", "AKIA-from-env"),
            ("AWS_SECRET_ACCESS_KEY", "secret-from-env"),
        ]));
        let resolved =
            resolve_chain(Some(yaml_creds), &env, Some(Path::new("/nonexistent"))).unwrap();
        assert_eq!(resolved.source, CredentialSource::FreedomYaml);
        assert_eq!(resolved.credentials.access_key_id.expose(), "AKIA-explicit");
    }

    #[test]
    fn env_vars_resolve_when_yaml_creds_absent() {
        let env = env_from(HashMap::from([
            ("AWS_ACCESS_KEY_ID", "AKIA-env"),
            ("AWS_SECRET_ACCESS_KEY", "secret-env"),
        ]));
        let resolved = resolve_chain(None, &env, Some(Path::new("/nonexistent"))).unwrap();
        assert_eq!(resolved.source, CredentialSource::EnvVars);
        assert_eq!(resolved.credentials.access_key_id.expose(), "AKIA-env");
        assert!(resolved.credentials.session_token.is_none());
    }

    #[test]
    fn session_token_threads_through_when_set_in_env() {
        let env = env_from(HashMap::from([
            ("AWS_ACCESS_KEY_ID", "AKIA-tmp"),
            ("AWS_SECRET_ACCESS_KEY", "secret-tmp"),
            ("AWS_SESSION_TOKEN", "session-token-blob"),
        ]));
        let resolved = resolve_chain(None, &env, Some(Path::new("/nonexistent"))).unwrap();
        let token = resolved.credentials.session_token.unwrap();
        assert_eq!(token.expose(), "session-token-blob");
    }

    #[test]
    fn empty_env_vars_treated_as_unset() {
        // Common operator footgun: `unset AWS_ACCESS_KEY_ID` left empty by
        // a shell script. Must NOT be treated as a valid empty key — that
        // would forge a 0-length signature.
        let env = env_from(HashMap::from([
            ("AWS_ACCESS_KEY_ID", ""),
            ("AWS_SECRET_ACCESS_KEY", "secret"),
        ]));
        let err = resolve_chain(None, &env, Some(Path::new("/nonexistent"))).unwrap_err();
        assert!(err.to_string().contains("no credentials found"));
    }

    #[test]
    fn missing_secret_in_env_falls_to_next_source_and_errs_when_no_file() {
        let env = env_from(HashMap::from([("AWS_ACCESS_KEY_ID", "AKIA-only-id")]));
        let err = resolve_chain(None, &env, Some(Path::new("/nonexistent"))).unwrap_err();
        assert!(err.to_string().contains("no credentials found"));
    }

    #[test]
    fn parses_default_profile_from_shared_credentials_file() {
        let body = "\
[default]
aws_access_key_id = AKIA-file
aws_secret_access_key = secret-file
aws_session_token = token-file

[other-profile]
aws_access_key_id = AKIA-other
aws_secret_access_key = secret-other
";
        let creds = parse_shared_credentials_default(body).unwrap();
        assert_eq!(creds.access_key_id.expose(), "AKIA-file");
        assert_eq!(creds.secret_access_key.expose(), "secret-file");
        assert_eq!(creds.session_token.unwrap().expose(), "token-file");
    }

    #[test]
    fn shared_credentials_default_can_appear_after_other_profiles() {
        let body = "\
[other]
aws_access_key_id = AKIA-other
aws_secret_access_key = secret-other

[default]
aws_access_key_id = AKIA-default
aws_secret_access_key = secret-default
";
        let creds = parse_shared_credentials_default(body).unwrap();
        assert_eq!(creds.access_key_id.expose(), "AKIA-default");
        assert_eq!(creds.secret_access_key.expose(), "secret-default");
    }

    #[test]
    fn shared_credentials_comments_and_blank_lines_ignored() {
        let body = "\
# this is a comment
; this too

[default]
# inline comment
aws_access_key_id = AKIA-clean
aws_secret_access_key = secret-clean
";
        let creds = parse_shared_credentials_default(body).unwrap();
        assert_eq!(creds.access_key_id.expose(), "AKIA-clean");
    }

    #[test]
    fn shared_credentials_credential_process_is_ignored() {
        // Security-auditor guardrail #1: credential_process is RCE-surface
        // and MUST be ignored even if present in the file.
        let body = "\
[default]
credential_process = /bin/evil --steal
aws_access_key_id = AKIA-still-static
aws_secret_access_key = secret-still-static
";
        let creds = parse_shared_credentials_default(body).unwrap();
        assert_eq!(creds.access_key_id.expose(), "AKIA-still-static");
        // The static keys still resolve — the dangerous directive is just
        // ignored. If only credential_process was present, the parse
        // returns None (no static keys to fall back on).
    }

    #[test]
    fn shared_credentials_only_credential_process_returns_none() {
        let body = "\
[default]
credential_process = /bin/evil
";
        assert!(parse_shared_credentials_default(body).is_none());
    }

    #[test]
    fn shared_credentials_default_missing_returns_none() {
        let body = "\
[only-other]
aws_access_key_id = AKIA-other
aws_secret_access_key = secret-other
";
        assert!(parse_shared_credentials_default(body).is_none());
    }

    #[test]
    fn shared_credentials_empty_file_returns_none() {
        assert!(parse_shared_credentials_default("").is_none());
        assert!(parse_shared_credentials_default("\n\n# nothing here\n").is_none());
    }

    #[test]
    fn shared_credentials_case_insensitive_default_header() {
        // `[Default]`, `[DEFAULT]` should all match — AWS CLI tolerates this.
        let body = "\
[DEFAULT]
aws_access_key_id = AKIA-upper
aws_secret_access_key = secret-upper
";
        let creds = parse_shared_credentials_default(body).unwrap();
        assert_eq!(creds.access_key_id.expose(), "AKIA-upper");
    }

    #[test]
    fn empty_home_env_produces_explicit_error() {
        // No env at all and no override → cannot locate ~/.aws/credentials.
        let env = env_from(HashMap::new());
        let err = resolve_chain(None, &env, None).unwrap_err();
        assert!(
            err.to_string().contains("USERPROFILE") || err.to_string().contains("home"),
            "got: {err}"
        );
    }

    #[test]
    fn debug_impl_redacts_all_secret_fields() {
        let creds = AwsCredentials {
            access_key_id: SecretString::new("AKIA-VERY-SECRET".into()),
            secret_access_key: SecretString::new("very-very-secret".into()),
            session_token: Some(SecretString::new("session-secret".into())),
        };
        let formatted = format!("{:?}", creds);
        assert!(!formatted.contains("VERY-SECRET"));
        assert!(!formatted.contains("session-secret"));
        assert!(formatted.contains("REDACTED"));
    }
}
