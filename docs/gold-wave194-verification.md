# Gold Wave 194 — n8n watchdog health probe

The watchdog now treats n8n as healthy only when the existing local n8n probe
receives a successful HTTP health/liveness response. A TCP listener, malformed
response, and non-2xx HTTP response are down outcomes and remain subject to
the existing watchdog restart policy, cooldowns and audit frames.

This is not an authenticated-readiness assertion. The probe only establishes
the bounded local HTTP health/liveness signal exposed by the n8n installer
probe.

Hosted regression identities:

- `daemon::watchdog_cron::tests::n8n_tcp_only_listener_is_not_healthy`
- `daemon::watchdog_cron::tests::n8n_malformed_http_response_is_not_healthy`
- `daemon::watchdog_cron::tests::n8n_http_503_is_not_healthy`
- `daemon::watchdog_cron::tests::n8n_successful_http_health_is_healthy`
