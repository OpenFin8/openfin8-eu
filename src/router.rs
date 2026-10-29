// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the OpenFin8:EU
// SPDX-License-Identifier: Apache-2.0

//! The EU adapter's router + state (OBARCH-7).
//!
//! The XS2A wire is adapter-owned (a different wire family from the
//! kernel's FDX surface - `openfin8-core/src/traits.rs` names it): the
//! kernel contributes the jurisdiction `Profile`
//! (`Profile::european_union()`) and the platform shell; the Consent API
//! (the four-state consent machine + the authorisation sub-resources +
//! the pre-step), the SCA ceremony routes, the PIS + signing-basket
//! surfaces, the AIS/PIIS resource surfaces, and the Extended Services
//! live here.
//!
//! Boot (the CA `server.rs` precedent): the shell's step-8 state build
//! receives the workload transports - the service's own `openfin8-eu`
//! pair, the `openfin8-eu-ledger` + `openfin8-eu-payments` proxy lanes
//! (CERTFREE-8V) - minted best-effort (the fleet may still be coming
//! up); a missing transport degrades loudly at the handler gate (503),
//! never silently.

use axum::routing::{get, post};
use openfin8_core::profile::Profile;

use crate::ais;
use crate::ceremony;
use crate::consent::{self, AppState};
use crate::extended;
use crate::payments;

/// Build a cert-presenting HTTP transport for `workload` (CERTFREE-4V,
/// the kernel `server.rs` precedent): mint-or-load the Acme-issued pair
/// and wrap it in a reqwest client. The receiving service's TLS layer
/// authenticates the handshake and the enroll-published registry map
/// authorizes the scopes - no bearer token exists on this path.
async fn build_workload_http(auth_issuer: &str, workload: &str) -> anyhow::Result<reqwest::Client> {
    let cert = sentin8::auth::m2m::ensure_workload_certificate(
        auth_issuer,
        workload,
        &sentin8::auth::m2m::platform_ca_path(),
    )
    .await?;
    let mtls = sentin8::middleware::mtls::MtlsConfig::new(
        &cert.ca_cert_path,
        &cert.cert_path,
        &cert.key_path,
    );
    sentin8::middleware::mtls::build_mtls_client(&mtls)
        .map_err(|e| anyhow::anyhow!("workload transport: {e}"))
}

/// Build the EU application state from the shell's core: the profile +
/// the boot-minted proxy lanes + the eIDAS configuration state.
pub async fn build_state(core: sentin8::shell::ServiceCore) -> anyhow::Result<AppState> {
    let profile = Profile::european_union();
    let cfg = sentin8::config::Sentin8Config::from_env();
    let auth_issuer =
        std::env::var("SENTIN8_AUTH_ISSUER").unwrap_or_else(|_| cfg.sentin8_auth_issuer());
    let ledger_url = std::env::var("BANK8_LEDGER_URL")
        .unwrap_or_else(|_| format!("https://{}", cfg.platform_domain("bank8:ledger")));
    let payments_url = std::env::var("BANK8_PAYMENTS_URL")
        .unwrap_or_else(|_| format!("https://{}", cfg.platform_domain("bank8:payments")));

    // The service's own workload transport (Flow registration rides it).
    let mut m2m_http = None;
    match build_workload_http(&auth_issuer, profile.workload()).await {
        Ok(http) => m2m_http = Some(http),
        Err(e) => {
            tracing::warn!(error = %e, "openfin8-eu workload transport unavailable - Flow registration degraded")
        }
    }
    // CERTFREE-8V: the proxy lanes' cross-service workloads. None → the
    // proxy lanes 503 loudly at the handler gate (never an
    // unauthenticated call).
    let ledger_http = match build_workload_http(&auth_issuer, "openfin8-eu-ledger").await {
        Ok(http) => Some(http),
        Err(e) => {
            tracing::warn!(error = %e, "ledger proxy transport unavailable - AIS reads degraded");
            None
        }
    };
    let payments_http = match build_workload_http(&auth_issuer, "openfin8-eu-payments").await {
        Ok(http) => Some(http),
        Err(e) => {
            tracing::warn!(error = %e, "payments proxy transport unavailable - PIS degraded");
            None
        }
    };

    // EU-4: the eIDAS certificate references (secret references only).
    // A partial/invalid configuration fails LOUDLY at boot (the pair is
    // a unit); absent = the PIS surface fails closed per-invocation.
    let eidas_configured = match crate::eidas::eidas_refs_from_env() {
        Ok(Some(_)) => true,
        Ok(None) => {
            tracing::warn!(
                "the eIDAS trust path is not configured (OPENFIN8_EU_QWAC/QSEALC_CERT/KEY_REF \
                 unset) - payment initiation fails closed"
            );
            false
        }
        Err(e) => {
            tracing::warn!(error = %e, "invalid eIDAS configuration - payment initiation fails closed");
            false
        }
    };

    let state = AppState::from_core(
        core,
        profile,
        ledger_http,
        ledger_url,
        payments_http,
        payments_url,
        eidas_configured,
    );

    // Register the EU ceremony step-handler profile with Flow (the
    // kernel contract; best-effort - the boot mint may be pending).
    if let Some(http) = m2m_http {
        let self_url = format!(
            "http://0.0.0.0:{}",
            std::env::var("PORT").unwrap_or_default()
        );
        let flow_url = std::env::var("SENTIN8_FLOW_URL").unwrap_or_else(|_| cfg.sentin8_flow_url());
        let body = serde_json::json!({
            "domain": state.profile.family,
            "base_url": self_url,
            "auth_token": "eu-dev",
            "internal_path": "/v1/internal/steps/execute",
            "step_kinds": ceremony::STEP_KINDS,
        });
        match http
            .post(format!(
                "{}/v1/handlers/register",
                flow_url.trim_end_matches('/')
            ))
            .json(&body)
            .send()
            .await
        {
            Ok(resp) if resp.status().is_success() => {}
            Ok(resp) => tracing::warn!("Flow register returned status {}", resp.status()),
            Err(e) => {
                tracing::warn!(error = %e, "failed to register the EU step handler profile with Flow")
            }
        }
    }
    Ok(state)
}

/// The served (method, path) table - the SINGLE source both `routes()`
/// and the OAPEC drift guard consume (a macro keeps the mount and the
/// table in lockstep: adding a route updates both or neither).
#[macro_export]
macro_rules! eu_routes {
    ($mount:expr) => {
        $mount
            // ── The Consent API: the four-state consent machine + the
            // authorisation sub-resources (the pre-step).
            .route("/v1/consents", post(consent::create_consent))
            .route("/v1/consents/{id}", get(consent::get_consent))
            .route("/v1/consents/{id}/status", get(consent::get_consent_status))
            .route(
                "/v1/consents/{id}/authorisations",
                post(consent::start_authorisation).get(consent::list_authorisations),
            )
            .route(
                "/v1/consents/{id}/authorisations/{authorisationId}",
                get(consent::get_authorisation),
            )
            // ── The SCA ceremonies (EU-3): redirect, decoupled, embedded.
            .route(
                "/v1/consents/{id}/authorisations/{authorisationId}/redirect",
                post(ceremony::start_redirect),
            )
            .route(
                "/v1/consents/{id}/authorisations/{authorisationId}/callback",
                post(ceremony::redirect_callback),
            )
            .route(
                "/v1/consents/{id}/authorisations/{authorisationId}/decoupled",
                post(ceremony::start_decoupled),
            )
            .route(
                "/v1/consents/{id}/authorisations/{authorisationId}/status",
                get(ceremony::poll_decoupled),
            )
            .route(
                "/v1/consents/{id}/authorisations/{authorisationId}/embedded",
                post(ceremony::start_embedded),
            )
            .route(
                "/v1/consents/{id}/authorisations/{authorisationId}/embedded/answer",
                post(ceremony::answer_embedded),
            )
            // ── PIS (EU-5): the ISO payment products + status + cancellation.
            .route(
                "/v1/payments/{paymentProduct}",
                post(payments::create_payment),
            )
            .route(
                "/v1/payments/{paymentProduct}/{paymentId}",
                get(payments::get_payment_status).delete(payments::cancel_payment),
            )
            // ── Signing baskets (EU-5): the batch authorization.
            .route("/v1/signing-baskets", post(payments::create_basket))
            .route("/v1/signing-baskets/{basketId}", get(payments::get_basket))
            // ── AIS (EU-6): the resource surfaces behind the chokepoint.
            .route(
                "/v1/ais/consents/{consentId}/accounts",
                get(ais::get_accounts),
            )
            .route(
                "/v1/ais/consents/{consentId}/accounts/{accountId}/balances",
                get(ais::get_balances),
            )
            .route(
                "/v1/ais/consents/{consentId}/accounts/{accountId}/transactions",
                get(ais::get_transactions),
            )
            .route(
                "/v1/ais/consents/{consentId}/card-accounts",
                get(ais::get_card_accounts),
            )
            // ── PIIS (EU-6): the funds-confirmation check.
            .route(
                "/v1/piis/consents/{consentId}/funds-confirmations",
                post(ais::confirm_funds),
            )
            // ── The Extended Services (EU-7).
            .route("/v1/discovery", get(extended::discovery))
            .route("/v1/mandates", get(extended::list_mandates))
            .route("/v1/request-to-pay", get(extended::list_request_to_pay))
            .route("/v1/push-ais", get(extended::list_push_ais))
            .route(
                "/v1/documents/{documentId}",
                get(extended::download_document),
            )
            // ── The Flow proxy-back lane (the ceremony step handler).
            .route(
                "/v1/internal/steps/execute",
                post(ceremony::execute_step_handler),
            )
    };
}

/// The served (method, path) pairs (the OAPEC drift guard's input; the
/// same list `routes()` mounts).
pub fn route_table() -> &'static [(&'static str, &'static str)] {
    &[
        ("POST", "/v1/consents"),
        ("GET", "/v1/consents/{id}"),
        ("GET", "/v1/consents/{id}/status"),
        ("POST", "/v1/consents/{id}/authorisations"),
        ("GET", "/v1/consents/{id}/authorisations"),
        ("GET", "/v1/consents/{id}/authorisations/{authorisationId}"),
        (
            "POST",
            "/v1/consents/{id}/authorisations/{authorisationId}/redirect",
        ),
        (
            "POST",
            "/v1/consents/{id}/authorisations/{authorisationId}/callback",
        ),
        (
            "POST",
            "/v1/consents/{id}/authorisations/{authorisationId}/decoupled",
        ),
        (
            "GET",
            "/v1/consents/{id}/authorisations/{authorisationId}/status",
        ),
        (
            "POST",
            "/v1/consents/{id}/authorisations/{authorisationId}/embedded",
        ),
        (
            "POST",
            "/v1/consents/{id}/authorisations/{authorisationId}/embedded/answer",
        ),
        ("POST", "/v1/payments/{paymentProduct}"),
        ("GET", "/v1/payments/{paymentProduct}/{paymentId}"),
        ("DELETE", "/v1/payments/{paymentProduct}/{paymentId}"),
        ("POST", "/v1/signing-baskets"),
        ("GET", "/v1/signing-baskets/{basketId}"),
        ("GET", "/v1/ais/consents/{consentId}/accounts"),
        (
            "GET",
            "/v1/ais/consents/{consentId}/accounts/{accountId}/balances",
        ),
        (
            "GET",
            "/v1/ais/consents/{consentId}/accounts/{accountId}/transactions",
        ),
        ("GET", "/v1/ais/consents/{consentId}/card-accounts"),
        ("POST", "/v1/piis/consents/{consentId}/funds-confirmations"),
        ("GET", "/v1/discovery"),
        ("GET", "/v1/mandates"),
        ("GET", "/v1/request-to-pay"),
        ("GET", "/v1/push-ais"),
        ("GET", "/v1/documents/{documentId}"),
        ("POST", "/v1/internal/steps/execute"),
    ]
}

/// The EU routes: the Consent API + the SCA ceremonies + PIS + signing
/// baskets + AIS/PIIS + the Extended Services (adapter-owned XS2A).
pub fn routes(router: axum::Router<AppState>, state: AppState) -> axum::Router<AppState> {
    eu_routes!(router).with_state(state)
}
