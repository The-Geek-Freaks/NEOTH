//! Narrow Paperless v3.2.1/API-v10 original-document protocol.
//! Pinned contract: paperless-ngx@7575d6078227ebdb4cf443f263d53ebc7575aa37.
//! Server filters produce candidates; exact filename, complete count and original
//! byte hashing establish observed document existence. No task/HTTP completion.

use anyhow::{Context, Result, ensure};
use futures_util::StreamExt;
use sha2::{Digest, Sha256};

use crate::wal::paperless_post_receipts::PaperlessPostIntentDescriptor;

pub(super) const MAX_ORIGINAL_BYTES: usize = 2 * 1024 * 1024;
const MAX_DOCUMENT_JSON_BYTES: usize = 16 * 1024 * 1024;

pub(super) struct VerifiedDocument {
    pub(super) id: u64,
    pub(super) original_sha256: String,
}

pub(super) struct PaperlessClient {
    client: reqwest::Client,
    documents: reqwest::Url,
    upload: reqwest::Url,
    authorization: reqwest::header::HeaderValue,
}

impl PaperlessClient {
    pub(super) fn new(endpoint: &str, token: &str) -> Result<Self> {
        let upload = reqwest::Url::parse(endpoint)?;
        ensure!(matches!(upload.scheme(), "http" | "https") && upload.host_str().is_some()
            && upload.username().is_empty() && upload.password().is_none()
            && upload.query().is_none() && upload.fragment().is_none()
            && upload.path().ends_with("/api/documents/post_document/"), "invalid Paperless upload endpoint");
        let documents = upload.join("../")?;
        let mut authorization = reqwest::header::HeaderValue::from_str(&format!("Token {token}"))?;
        authorization.set_sensitive(true);
        let client = reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(5))
            .timeout(std::time::Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        Ok(Self { client, documents, upload, authorization })
    }

    fn request(&self, method: reqwest::Method, url: reqwest::Url) -> reqwest::RequestBuilder {
        self.client.request(method, url)
            .header(reqwest::header::AUTHORIZATION, self.authorization.clone())
            .header(reqwest::header::ACCEPT, "application/json; version=10")
    }

    fn validate_request(&self, descriptor: &PaperlessPostIntentDescriptor) -> Result<()> {
        descriptor.validate()?;
        // Use the canonical endpoint bytes used at intent construction. A later
        // config change cannot reconcile against a different Paperless target.
        let expected = PaperlessPostIntentDescriptor::from_mail("", 0, "", "", "", "", self.upload.as_str());
        ensure!(expected.destination_sha256 == descriptor.destination_sha256,
            "Paperless reconciliation destination differs from intent");
        ensure!(!descriptor.is_completion(), "Paperless client requires an intent descriptor");
        Ok(())
    }

    pub(super) fn validate_request_parts(&self, descriptor: &PaperlessPostIntentDescriptor, title: &str, body: &str) -> Result<()> {
        self.validate_request(descriptor)?;
        ensure!(body.len() <= MAX_ORIGINAL_BYTES && hex::encode(Sha256::digest(body.as_bytes())) == descriptor.body_sha256,
            "Paperless upload bytes differ from admitted request or exceed verification bound");
        let title_binding = PaperlessPostIntentDescriptor::from_mail("", 0, "", "", "", title, self.upload.as_str());
        ensure!(title_binding.title_sha256 == descriptor.title_sha256, "Paperless upload title differs from intent");
        Ok(())
    }

    pub(super) async fn upload(&self, descriptor: &PaperlessPostIntentDescriptor, title: &str, body: &str) -> Result<u16> {
        self.validate_request_parts(descriptor, title, body)?;
        let form = reqwest::multipart::Form::new().text("title", title.to_owned()).part(
            "document", reqwest::multipart::Part::bytes(body.as_bytes().to_vec())
                .file_name(descriptor.marker_filename()).mime_str("text/plain")?,
        );
        let response = self.request(reqwest::Method::POST, self.upload.clone())
            .multipart(form).send().await.context("Paperless upload transport")?;
        Ok(response.status().as_u16())
    }

    /// A missing result is pending, not evidence that a previous POST failed.
    /// A supported, successful list response also validates API access before a
    /// first claim. Unsupported versions, permissions and malformed envelopes
    /// fail before a new upload is attempted.
    pub(super) async fn reconcile(&self, descriptor: &PaperlessPostIntentDescriptor) -> Result<Option<VerifiedDocument>> {
        self.validate_request(descriptor)?;
        let marker = descriptor.marker_filename();
        let response = self.request(reqwest::Method::GET, self.documents.clone())
            .query(&[("original_filename__iexact", marker.as_str()), ("page_size", "2")])
            .send().await.context("Paperless document lookup")?;
        ensure!(response.status() == reqwest::StatusCode::OK
            && response.headers().get("X-Api-Version").and_then(|value| value.to_str().ok()) == Some("10")
            && response.headers().get("X-Version").and_then(|value| value.to_str().ok()) == Some("3.2.1"),
            "Paperless server does not match the reviewed v3.2.1/API-v10 contract");
        let bytes = bounded_response(response, MAX_DOCUMENT_JSON_BYTES).await?;
        let value: serde_json::Value = serde_json::from_slice(&bytes).context("Paperless document envelope")?;
        let count = value.get("count").and_then(serde_json::Value::as_u64).context("Paperless result count")?;
        let results = value.get("results").and_then(serde_json::Value::as_array).context("Paperless document results")?;
        ensure!(value.get("next") == Some(&serde_json::Value::Null)
            && value.get("previous") == Some(&serde_json::Value::Null), "incomplete Paperless result page");
        if count == 0 && results.is_empty() { return Ok(None); }
        ensure!(count == 1 && results.len() == 1, "ambiguous Paperless marker");
        let document = &results[0];
        ensure!(document.get("original_file_name").and_then(serde_json::Value::as_str) == Some(marker.as_str()),
            "Paperless original filename differs from marker");
        let id = document.get("id").and_then(serde_json::Value::as_u64).filter(|id| *id > 0)
            .context("invalid Paperless document identity")?;
        let download = self.documents.join(&format!("{id}/download/"))?;
        let response = self.request(reqwest::Method::GET, download)
            .query(&[("original", "true")]).send().await.context("Paperless original download")?;
        ensure!(response.status() == reqwest::StatusCode::OK, "Paperless original download is not a complete 200 response");
        let original = bounded_response(response, MAX_ORIGINAL_BYTES).await?;
        let original_sha256 = hex::encode(Sha256::digest(&original));
        ensure!(original_sha256 == descriptor.body_sha256, "Paperless original bytes differ from intent");
        Ok(Some(VerifiedDocument { id, original_sha256 }))
    }
}

async fn bounded_response(response: reqwest::Response, cap: usize) -> Result<Vec<u8>> {
    ensure!(response.status().is_success(), "Paperless response does not confirm a readable resource");
    ensure!(response.content_length().is_none_or(|length| length <= cap as u64), "Paperless response exceeds bound");
    let mut body = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.context("Paperless response interrupted")?;
        ensure!(chunk.len() <= cap.saturating_sub(body.len()), "Paperless streamed response exceeds bound");
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use wiremock::{Mock, MockServer, ResponseTemplate};
    use wiremock::matchers::{method, path, query_param};

    fn descriptor(server: &MockServer) -> PaperlessPostIntentDescriptor {
        PaperlessPostIntentDescriptor::from_mail("mail.example", 993, "fixture", "mail", "original bytes", "invoice",
            &format!("{}/api/documents/post_document/", server.uri()))
    }

    fn envelope(value: serde_json::Value) -> ResponseTemplate {
        ResponseTemplate::new(200).insert_header("X-Version", "3.2.1")
            .insert_header("X-Api-Version", "10").set_body_json(value)
    }

    #[tokio::test]
    async fn exact_document_reconciliation_downloads_original_bytes() {
        let server = MockServer::start().await;
        let descriptor = descriptor(&server);
        Mock::given(method("GET")).and(path("/api/documents/"))
            .and(query_param("original_filename__iexact", descriptor.marker_filename()))
            .and(query_param("page_size", "2"))
            .respond_with(envelope(json!({"count":1,"next":null,"previous":null,"results":[{"id":7,"original_file_name":descriptor.marker_filename()}]})))
            .expect(1).mount(&server).await;
        Mock::given(method("GET")).and(path("/api/documents/7/download/"))
            .and(query_param("original", "true"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"original bytes".to_vec()))
            .expect(1).mount(&server).await;
        let client = PaperlessClient::new(&format!("{}/api/documents/post_document/", server.uri()), "fixture-token").unwrap();
        let verified = client.reconcile(&descriptor).await.unwrap().unwrap();
        assert_eq!(verified.id, 7);
        assert_eq!(verified.original_sha256, descriptor.body_sha256);
        assert!(descriptor.with_verified_document(verified.id, &verified.original_sha256).is_ok());
    }

    #[tokio::test]
    async fn document_reconciliation_rejects_ambiguous_incomplete_or_wrong_filename_rows() {
        let server = MockServer::start().await;
        let descriptor = descriptor(&server);
        let client = PaperlessClient::new(&format!("{}/api/documents/post_document/", server.uri()), "fixture-token").unwrap();
        let valid = json!({"id":7,"original_file_name":descriptor.marker_filename()});
        for value in [
            json!({"count":2,"next":null,"previous":null,"results":[valid.clone(),valid.clone()]}),
            json!({"count":1,"next":"https://foreign.invalid/next","previous":null,"results":[valid.clone()]}),
            json!({"count":1,"next":null,"previous":null,"results":[{"id":7,"original_file_name":"another.txt"}]}),
            json!({"count":1,"next":null,"previous":null,"results":[]}),
            json!({"count":"1","next":null,"previous":null,"results":[valid.clone()]}),
            json!({"count":1,"next":null,"previous":null,"results":[{"id":0,"original_file_name":descriptor.marker_filename()}]}),
        ] {
            server.reset().await;
            Mock::given(method("GET")).and(path("/api/documents/"))
                .respond_with(envelope(value)).mount(&server).await;
            assert!(client.reconcile(&descriptor).await.is_err());
            assert_eq!(server.received_requests().await.unwrap().len(), 1);
        }
    }

    #[tokio::test]
    async fn document_reconciliation_rejects_unsupported_server_before_any_effect() {
        let server = MockServer::start().await;
        let descriptor = descriptor(&server);
        let client = PaperlessClient::new(&format!("{}/api/documents/post_document/", server.uri()), "fixture-token").unwrap();
        Mock::given(method("GET")).and(path("/api/documents/"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"count":0,"next":null,"previous":null,"results":[]})))
            .mount(&server).await;
        assert!(client.reconcile(&descriptor).await.is_err());
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
        let other = PaperlessClient::new("http://different.invalid/api/documents/post_document/", "fixture-token").unwrap();
        assert!(other.reconcile(&descriptor).await.is_err());
    }

    #[tokio::test]
    async fn empty_original_requires_200_not_no_content_or_partial_response() {
        let server = MockServer::start().await;
        let endpoint = format!("{}/api/documents/post_document/", server.uri());
        let descriptor = PaperlessPostIntentDescriptor::from_mail("mail.example", 993, "fixture", "empty", "", "invoice", &endpoint);
        let client = PaperlessClient::new(&endpoint, "fixture-token").unwrap();
        for status in [204, 206] {
            server.reset().await;
            Mock::given(method("GET")).and(path("/api/documents/"))
                .respond_with(envelope(json!({"count":1,"next":null,"previous":null,"results":[{"id":7,"original_file_name":descriptor.marker_filename()}]})))
                .mount(&server).await;
            Mock::given(method("GET")).and(path("/api/documents/7/download/"))
                .respond_with(ResponseTemplate::new(status).set_body_bytes(Vec::<u8>::new())).mount(&server).await;
            assert!(client.reconcile(&descriptor).await.is_err());
        }
    }

    #[tokio::test]
    async fn document_reconciliation_rejects_wrong_oversize_and_redirected_originals() {
        let server = MockServer::start().await;
        let descriptor = descriptor(&server);
        let client = PaperlessClient::new(&format!("{}/api/documents/post_document/", server.uri()), "fixture-token").unwrap();
        for original in [
            ResponseTemplate::new(200).set_body_bytes(b"wrong bytes".to_vec()),
            ResponseTemplate::new(200).set_body_bytes(vec![b'x'; MAX_ORIGINAL_BYTES + 1]),
            ResponseTemplate::new(302).insert_header("Location", "https://foreign.invalid/document"),
        ] {
            server.reset().await;
            Mock::given(method("GET")).and(path("/api/documents/"))
                .respond_with(envelope(json!({"count":1,"next":null,"previous":null,"results":[{"id":7,"original_file_name":descriptor.marker_filename()}]})))
                .mount(&server).await;
            Mock::given(method("GET")).and(path("/api/documents/7/download/"))
                .respond_with(original).mount(&server).await;
            assert!(client.reconcile(&descriptor).await.is_err());
            assert_eq!(server.received_requests().await.unwrap().len(), 2);
        }
    }

    #[tokio::test]
    async fn upload_rejects_unbound_parts_before_transport_and_retains_exact_marker() {
        let server = MockServer::start().await;
        let descriptor = descriptor(&server);
        let client = PaperlessClient::new(&format!("{}/api/documents/post_document/", server.uri()), "fixture-token").unwrap();
        assert!(client.upload(&descriptor, "wrong title", "original bytes").await.is_err());
        assert!(client.upload(&descriptor, "invoice", "wrong body").await.is_err());
        assert!(server.received_requests().await.unwrap().is_empty());
        Mock::given(method("POST")).and(path("/api/documents/post_document/"))
            .respond_with(ResponseTemplate::new(202)).expect(1).mount(&server).await;
        assert_eq!(client.upload(&descriptor, "invoice", "original bytes").await.unwrap(), 202);
        let requests = server.received_requests().await.unwrap();
        let body = String::from_utf8_lossy(&requests[0].body);
        assert!(body.contains(&format!("filename=\"{}\"", descriptor.marker_filename())));
        assert!(body.contains("original bytes"));
        assert_eq!(requests[0].headers.get("accept").unwrap(), "application/json; version=10");
    }
}
