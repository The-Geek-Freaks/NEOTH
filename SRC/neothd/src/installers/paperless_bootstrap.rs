//! Local-only first-boot token acquisition for an already verified Paperless
//! container. This module never starts Docker and never exposes credentials in
//! diagnostics.

use std::{collections::BTreeMap, path::Path, time::Duration};

use futures_util::StreamExt;
use reqwest::{Client, Url, header};
use serde::Deserialize;
use zeroize::Zeroizing;

use crate::{
    config::{FreedomConfig, SecretsBackend, credentials::Credentials},
    secret::SecretString,
};

const ENV_LIMIT: usize = 16 * 1024;
const BODY_LIMIT: usize = 32 * 1024;
const TOKEN_LIMIT: usize = 4096;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

/// Administrator credentials read from the instance-owned `paperless.env`.
/// The fields deliberately remain private so callers cannot accidentally log
/// them while handling bootstrap failures.
pub(crate) struct BootstrapAdmin {
    username: SecretString,
    password: SecretString,
}

impl BootstrapAdmin {
    /// Parse only the two Paperless administrator fields from a bounded,
    /// literal dotenv file. Shell expansion and duplicate required keys are
    /// rejected instead of being interpreted differently by a shell later.
    pub(crate) fn from_env_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() > ENV_LIMIT {
            return Err("paperless_bootstrap_env_too_large");
        }
        let text = std::str::from_utf8(bytes).map_err(|_| "paperless_bootstrap_env_invalid")?;
        let mut values = BTreeMap::new();
        for raw_line in text.lines() {
            let line = raw_line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (name, raw_value) = line
                .split_once('=')
                .ok_or("paperless_bootstrap_env_invalid")?;
            let name = name.trim();
            if name.is_empty()
                || !name.bytes().enumerate().all(|(index, byte)| {
                    byte == b'_'
                        || byte.is_ascii_alphanumeric() && (index > 0 || !byte.is_ascii_digit())
                })
            {
                return Err("paperless_bootstrap_env_invalid");
            }
            if !matches!(name, "PAPERLESS_ADMIN_USER" | "PAPERLESS_ADMIN_PASSWORD") {
                continue;
            }
            if values.contains_key(name) {
                return Err("paperless_bootstrap_env_duplicate");
            }
            values.insert(name, parse_dotenv_value(raw_value)?);
        }
        let username = values
            .remove("PAPERLESS_ADMIN_USER")
            .filter(|value| !value.is_empty())
            .ok_or("paperless_bootstrap_admin_missing")?;
        let password = values
            .remove("PAPERLESS_ADMIN_PASSWORD")
            .filter(|value| !value.is_empty())
            .ok_or("paperless_bootstrap_admin_missing")?;
        Ok(Self {
            username: SecretString::new(username.to_string()),
            password: SecretString::new(password.to_string()),
        })
    }
}

fn parse_dotenv_value(raw: &str) -> Result<Zeroizing<String>, &'static str> {
    let value = raw.trim();
    let parsed = if let Some(inner) = value.strip_prefix('\'') {
        let inner = inner
            .strip_suffix('\'')
            .ok_or("paperless_bootstrap_env_invalid")?;
        if inner.contains('\'') {
            return Err("paperless_bootstrap_env_invalid");
        }
        inner.to_owned()
    } else if let Some(inner) = value.strip_prefix('"') {
        let inner = inner
            .strip_suffix('"')
            .ok_or("paperless_bootstrap_env_invalid")?;
        let mut output = String::with_capacity(inner.len());
        let mut escaped = false;
        for character in inner.chars() {
            if escaped {
                match character {
                    '\\' => output.push('\\'),
                    '"' => output.push('"'),
                    'n' => output.push('\n'),
                    'r' => output.push('\r'),
                    't' => output.push('\t'),
                    _ => return Err("paperless_bootstrap_env_invalid"),
                }
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == '"' {
                return Err("paperless_bootstrap_env_invalid");
            } else {
                output.push(character);
            }
        }
        if escaped {
            return Err("paperless_bootstrap_env_invalid");
        }
        output
    } else {
        // Docker Compose recognizes an inline comment only when its `#` is
        // preceded by whitespace. Mirror that rule so Paperless and NEOTH
        // never authenticate with different raw administrator values.
        let without_comment = value
            .char_indices()
            .find_map(|(index, character)| {
                (character == '#'
                    && value[..index]
                        .chars()
                        .last()
                        .is_some_and(char::is_whitespace))
                .then_some(&value[..index])
            })
            .unwrap_or(value)
            .trim_end();
        without_comment.to_owned()
    };
    if parsed.contains('$') || parsed.contains('`') || parsed.contains('\0') {
        return Err("paperless_bootstrap_env_ambiguous");
    }
    Ok(Zeroizing::new(parsed))
}

/// Obtain a Paperless API token from the literal, verified IPv4 loopback
/// origin. Redirects, proxies, non-JSON bodies, and oversized responses are
/// rejected.
pub(crate) async fn obtain_token(
    origin: &str,
    admin: &BootstrapAdmin,
) -> Result<SecretString, &'static str> {
    let origin = canonical_bootstrap_origin(origin)?;
    let client = Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(REQUEST_TIMEOUT)
        .build()
        .map_err(|_| "paperless_bootstrap_transport")?;
    tokio::time::timeout(REQUEST_TIMEOUT, async {
        let response = client
            .post(format!("{origin}/api/token/"))
            .form(&[
                ("username", admin.username.expose_secret()),
                ("password", admin.password.expose_secret()),
            ])
            .send()
            .await
            .map_err(|_| "paperless_bootstrap_transport")?;
        if response.status().is_redirection() {
            return Err("paperless_bootstrap_redirect");
        }
        if !response.status().is_success() {
            return Err("paperless_bootstrap_token_rejected");
        }
        if !is_json_content_type(response.headers().get(header::CONTENT_TYPE)) {
            return Err("paperless_bootstrap_token_response_invalid");
        }
        let body = bounded_body(response).await?;
        let response: TokenResponse = serde_json::from_slice(&body)
            .map_err(|_| "paperless_bootstrap_token_response_invalid")?;
        if response.token.expose_secret().is_empty()
            || response.token.expose_secret().len() > TOKEN_LIMIT
        {
            return Err("paperless_bootstrap_token_response_invalid");
        }
        Ok(response.token)
    })
    .await
    .map_err(|_| "paperless_bootstrap_timeout")?
}

fn is_json_content_type(value: Option<&header::HeaderValue>) -> bool {
    let Some(value) = value.and_then(|value| value.to_str().ok()) else {
        return false;
    };
    let media_type = value.split(';').next().unwrap_or_default().trim();
    media_type.eq_ignore_ascii_case("application/json")
        || media_type
            .strip_prefix("application/")
            .is_some_and(|subtype| subtype.to_ascii_lowercase().ends_with("+json"))
}

#[derive(Deserialize)]
struct TokenResponse {
    token: SecretString,
}

async fn bounded_body(response: reqwest::Response) -> Result<Zeroizing<Vec<u8>>, &'static str> {
    let mut body = Zeroizing::new(Vec::new());
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| "paperless_bootstrap_transport")?;
        if body.len().saturating_add(chunk.len()) > BODY_LIMIT {
            return Err("paperless_bootstrap_response_too_large");
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// Persist only a newly bootstrapped token. The expected backend and URL must
/// still match under the paired config/credential transaction before anything
/// is replaced. A configured keychain receives the secret directly; writing a
/// YAML fallback there would silently override the keychain on later loads.
pub(crate) fn persist_bootstrap_at(
    home: &Path,
    expected_backend: SecretsBackend,
    expected_url: Option<&str>,
    origin: &str,
    token: &SecretString,
) -> Result<(), &'static str> {
    if token.expose_secret().is_empty() || token.expose_secret().len() > TOKEN_LIMIT {
        return Err("paperless_bootstrap_token_invalid");
    }
    let origin = canonical_bootstrap_origin(origin)?;
    if expected_url.is_some_and(|url| url != origin) {
        return Err("paperless_bootstrap_url_changed");
    }
    let freedom_path = home.join("freedom.yaml");
    let credentials_path = home.join("credentials.yaml");
    Credentials::update_raw_freedom_with_credentials_at(
        &freedom_path,
        &credentials_path,
        |source, credentials| {
            let backend = source
                .map(serde_yaml::from_str::<FreedomConfig>)
                .transpose()
                .map_err(|_| anyhow::anyhow!("paperless_bootstrap_config_invalid"))?
                .map(|config| config.secrets_backend)
                .unwrap_or(SecretsBackend::File);
            if backend != expected_backend {
                return Err(anyhow::anyhow!("paperless_bootstrap_backend_changed"));
            }
            if credentials.paperless_token.is_some() {
                return Err(anyhow::anyhow!("paperless_bootstrap_token_conflict"));
            }
            match credentials.paperless_url.as_deref() {
                Some(url) if url != origin => {
                    return Err(anyhow::anyhow!("paperless_bootstrap_url_changed"));
                }
                Some(_) => {}
                None => credentials.paperless_url = Some(origin.clone()),
            }
            match backend {
                SecretsBackend::File => credentials.paperless_token = Some(token.clone()),
                SecretsBackend::Keychain => {
                    let store = crate::config::keychain::open_store()
                        .map_err(|_| anyhow::anyhow!("paperless_bootstrap_keychain"))?;
                    if store
                        .get("paperless_token")
                        .map_err(|_| anyhow::anyhow!("paperless_bootstrap_keychain"))?
                        .is_some()
                    {
                        return Err(anyhow::anyhow!("paperless_bootstrap_token_conflict"));
                    }
                    // Keep the keychain side effect outside this paired-file
                    // publication. A publication failure must not strand a
                    // token whose URL/config generation never committed.
                }
            }
            Ok((None, ()))
        },
    )
    .map_err(|error| match error.to_string().as_str() {
        "paperless_bootstrap_backend_changed" => "paperless_bootstrap_backend_changed",
        "paperless_bootstrap_token_conflict" => "paperless_bootstrap_token_conflict",
        "paperless_bootstrap_url_changed" => "paperless_bootstrap_url_changed",
        "paperless_bootstrap_keychain" => "paperless_bootstrap_keychain",
        "paperless_bootstrap_config_invalid" => "paperless_bootstrap_config_invalid",
        _ => "paperless_bootstrap_persist",
    })?;
    if expected_backend == SecretsBackend::Keychain {
        persist_keychain_token_after_url(&freedom_path, &origin, token)?;
    }
    Ok(())
}

/// Set the OS credential only after the paired URL publication committed. The
/// current config-authority lock makes a concurrent supported credential writer
/// wait; a token discovered here is an operator/concurrent conflict and is
/// never overwritten.
fn persist_keychain_token_after_url(
    freedom_path: &Path,
    origin: &str,
    token: &SecretString,
) -> Result<(), &'static str> {
    let store =
        crate::config::keychain::open_store().map_err(|_| "paperless_bootstrap_keychain")?;
    persist_keychain_token_after_url_with_store(freedom_path, origin, token, store.as_ref())
}

fn persist_keychain_token_after_url_with_store(
    freedom_path: &Path,
    origin: &str,
    token: &SecretString,
    store: &dyn crate::config::keychain::SecretStore,
) -> Result<(), &'static str> {
    crate::config::with_current_freedom_config_authority_locked(freedom_path, |config| {
        if config.secrets_backend != SecretsBackend::Keychain {
            return Err(anyhow::anyhow!("paperless_bootstrap_backend_changed"));
        }
        // This is a same-home re-entrant coherent reader. It reloads the
        // effective pair after the URL publication, including an operator's
        // file override and the OS-store supplement, before this final set.
        let (_, effective) =
            crate::config::load_optional_runtime_config_pair_read_only_with_store_from_path(
                freedom_path,
                Some(store),
            )
            .map_err(|_| anyhow::anyhow!("paperless_bootstrap_persist"))?;
        if effective.paperless_url.as_deref() != Some(origin) {
            return Err(anyhow::anyhow!("paperless_bootstrap_url_changed"));
        }
        if effective.paperless_token.is_some() {
            return Err(anyhow::anyhow!("paperless_bootstrap_token_conflict"));
        }
        store_token_if_absent(store, token)?;
        Ok(())
    })
    .map_err(|error| match error.to_string().as_str() {
        "paperless_bootstrap_backend_changed" => "paperless_bootstrap_backend_changed",
        "paperless_bootstrap_token_conflict" => "paperless_bootstrap_token_conflict",
        "paperless_bootstrap_url_changed" => "paperless_bootstrap_url_changed",
        "paperless_bootstrap_keychain" => "paperless_bootstrap_keychain",
        _ => "paperless_bootstrap_persist",
    })
}

fn store_token_if_absent(
    store: &dyn crate::config::keychain::SecretStore,
    token: &SecretString,
) -> anyhow::Result<()> {
    if store
        .get("paperless_token")
        .map_err(|_| anyhow::anyhow!("paperless_bootstrap_keychain"))?
        .is_some()
    {
        return Err(anyhow::anyhow!("paperless_bootstrap_token_conflict"));
    }
    store
        .set("paperless_token", token)
        .map_err(|_| anyhow::anyhow!("paperless_bootstrap_keychain"))
}

fn canonical_bootstrap_origin(origin: &str) -> Result<String, &'static str> {
    let url = Url::parse(origin).map_err(|_| "paperless_bootstrap_origin_invalid")?;
    if url.scheme() != "http"
        || url.host_str() != Some("127.0.0.1")
        || matches!(url.port(), None | Some(0))
        || url.username() != ""
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err("paperless_bootstrap_origin_invalid");
    }
    Ok(format!(
        "http://127.0.0.1:{}",
        url.port().unwrap_or_default()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dotenv_parser_accepts_literal_and_basic_quoted_admin_values() {
        let admin = BootstrapAdmin::from_env_bytes(
            b"PAPERLESS_ADMIN_USER='operator'\nPAPERLESS_ADMIN_PASSWORD=\"pass\\\\word\"\n",
        )
        .unwrap();
        assert_eq!(admin.username.expose_secret(), "operator");
        assert_eq!(admin.password.expose_secret(), "pass\\word");
    }

    #[test]
    fn dotenv_parser_rejects_ambiguous_or_duplicate_admin_values() {
        assert!(matches!(
            BootstrapAdmin::from_env_bytes(
                b"PAPERLESS_ADMIN_USER=operator\nPAPERLESS_ADMIN_USER=other\nPAPERLESS_ADMIN_PASSWORD=pass\n"
            ),
            Err("paperless_bootstrap_env_duplicate")
        ));
        let parsed = BootstrapAdmin::from_env_bytes(
            b"PAPERLESS_ADMIN_USER=operator # comment\nPAPERLESS_ADMIN_PASSWORD=secret # comment\n",
        )
        .unwrap();
        assert_eq!(parsed.password.expose_secret(), "secret");
        let quoted = BootstrapAdmin::from_env_bytes(
            b"PAPERLESS_ADMIN_USER=operator\nPAPERLESS_ADMIN_PASSWORD='secret # literal'\n",
        )
        .unwrap();
        assert_eq!(quoted.password.expose_secret(), "secret # literal");
        assert!(matches!(
            BootstrapAdmin::from_env_bytes(
                b"PAPERLESS_ADMIN_USER=$USER\nPAPERLESS_ADMIN_PASSWORD=pass\n"
            ),
            Err("paperless_bootstrap_env_ambiguous")
        ));
    }

    #[test]
    fn canonical_origin_accepts_only_literal_ipv4_loopback() {
        assert_eq!(
            canonical_bootstrap_origin("http://127.0.0.1:18000").unwrap(),
            "http://127.0.0.1:18000"
        );
        assert!(canonical_bootstrap_origin("http://localhost:18000").is_err());
        assert!(canonical_bootstrap_origin("http://127.0.0.1:0").is_err());
        assert!(canonical_bootstrap_origin("http://127.0.0.1:18000/base").is_err());
        assert!(
            is_json_content_type(Some(&header::HeaderValue::from_static("text/plain"))) == false
        );
        assert!(is_json_content_type(Some(
            &header::HeaderValue::from_static("application/problem+json; charset=utf-8")
        )));
    }

    #[test]
    fn file_persistence_refuses_existing_token_and_preserves_url() {
        let home = tempfile::tempdir().unwrap();
        let token = SecretString::from("new-token");
        persist_bootstrap_at(
            home.path(),
            SecretsBackend::File,
            None,
            "http://127.0.0.1:18000",
            &token,
        )
        .unwrap();
        let credentials =
            Credentials::load_or_default(&home.path().join("credentials.yaml")).unwrap();
        assert_eq!(
            credentials.paperless_url.as_deref(),
            Some("http://127.0.0.1:18000")
        );
        assert_eq!(
            credentials.paperless_token.unwrap().expose_secret(),
            "new-token"
        );
        assert_eq!(
            persist_bootstrap_at(
                home.path(),
                SecretsBackend::File,
                Some("http://127.0.0.1:18000"),
                "http://127.0.0.1:18000",
                &token,
            )
            .unwrap_err(),
            "paperless_bootstrap_token_conflict"
        );
    }

    #[test]
    fn keychain_write_follows_real_pair_publication_and_rechecks_effective_state() {
        use crate::config::keychain::{InMemorySecretStore, SecretStore};

        let home = tempfile::tempdir().unwrap();
        let freedom_path = home.path().join("freedom.yaml");
        let credentials_path = home.path().join("credentials.yaml");
        std::fs::write(&freedom_path, "secrets_backend: keychain\n").unwrap();
        let store = InMemorySecretStore::default();
        let token = SecretString::from("issued-token");
        let failed = Credentials::test_update_raw_freedom_with_credentials_at_using_fault(
            &freedom_path,
            &credentials_path,
            |_, credentials| {
                credentials.paperless_url = Some("http://127.0.0.1:18000".to_owned());
                Ok((None, ()))
            },
            crate::config::credentials::DualFileTestFaultPoint::JournalPrepared,
        );
        assert!(failed.is_err());
        assert!(store.get("paperless_token").unwrap().is_none());

        Credentials::update_raw_freedom_with_credentials_at(
            &freedom_path,
            &credentials_path,
            |_, credentials| {
                credentials.paperless_url = Some("http://127.0.0.1:18000".to_owned());
                Ok((None, ()))
            },
        )
        .unwrap();
        persist_keychain_token_after_url_with_store(
            &freedom_path,
            "http://127.0.0.1:18000",
            &token,
            &store,
        )
        .unwrap();
        assert_eq!(
            store
                .get("paperless_token")
                .unwrap()
                .unwrap()
                .expose_secret(),
            "issued-token"
        );
        assert_eq!(
            persist_keychain_token_after_url_with_store(
                &freedom_path,
                "http://127.0.0.1:18000",
                &token,
                &store,
            )
            .unwrap_err(),
            "paperless_bootstrap_token_conflict"
        );

        let other_store = InMemorySecretStore::default();
        Credentials::update_raw_freedom_with_credentials_at(
            &freedom_path,
            &credentials_path,
            |_, credentials| {
                credentials.paperless_url = Some("http://127.0.0.1:18001".to_owned());
                Ok((None, ()))
            },
        )
        .unwrap();
        assert_eq!(
            persist_keychain_token_after_url_with_store(
                &freedom_path,
                "http://127.0.0.1:18000",
                &token,
                &other_store,
            )
            .unwrap_err(),
            "paperless_bootstrap_url_changed"
        );
        assert!(other_store.get("paperless_token").unwrap().is_none());

        Credentials::update_raw_freedom_with_credentials_at(
            &freedom_path,
            &credentials_path,
            |_, credentials| {
                credentials.paperless_url = Some("http://127.0.0.1:18000".to_owned());
                credentials.paperless_token = Some(SecretString::from("operator-token"));
                Ok((None, ()))
            },
        )
        .unwrap();
        assert_eq!(
            persist_keychain_token_after_url_with_store(
                &freedom_path,
                "http://127.0.0.1:18000",
                &token,
                &other_store,
            )
            .unwrap_err(),
            "paperless_bootstrap_token_conflict"
        );
        assert!(other_store.get("paperless_token").unwrap().is_none());
    }

    #[tokio::test]
    async fn obtains_token_from_a_bounded_local_http_endpoint() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            loop {
                let mut byte = [0];
                stream.read_exact(&mut byte).await.unwrap();
                request.push(byte[0]);
                if request.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            assert!(
                std::str::from_utf8(&request)
                    .unwrap()
                    .starts_with("POST /api/token/ HTTP/1.1")
            );
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 23\r\n\r\n{\"token\":\"local-token\"}")
                .await
                .unwrap();
        });
        let admin = BootstrapAdmin::from_env_bytes(
            b"PAPERLESS_ADMIN_USER=operator\nPAPERLESS_ADMIN_PASSWORD=password\n",
        )
        .unwrap();
        let token = obtain_token(&format!("http://127.0.0.1:{port}"), &admin)
            .await
            .unwrap();
        task.await.unwrap();
        assert_eq!(token.expose_secret(), "local-token");
    }
}
