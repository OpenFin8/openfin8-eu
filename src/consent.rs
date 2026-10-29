// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the OpenFin8:EU
// SPDX-License-Identifier: Apache-2.0

//! The XS2A consent + authorisation model- EU DESIGN.md §2
//! Consent API row, §3 ceremony 4, §7 invariants).
//!
//! Two separate state machines that are NEVER conflated (DESIGN.md §7):
//!
//! - the **consent** rides the kernel's states rendered as the four-state
//!   XS2A machine: `received` (kernel `awaiting_authorization`) → `valid`
//!   (kernel `active`) → `rejected` (the deny path) / `expired` /
//!   `revoked` (terminal, always);
//! - each consent carries explicit **authorisation sub-resources** - every
//!   SCA ceremony is its own object with its own per-approach state
//!   machine (`received` → `psu_identified` → `psu_authenticated` →
//!   `sca_started` → `finalised` | `failed` | `expired`), created by the
//!   **pre-step** (`startAuthorisation`, optionally selecting the SCA
//!   approach before the PSU ceremony begins).
//!
//! SCA success (an authorisation reaching `finalised`) never mutates the
//! consent directly: the consent transitions when the adapter observes
//! the authorisation outcome (`valid` when the PSU ceremony completes).
//! The per-approach step sequences are Flow-driven; this module
//! owns the model + the Consent API routes over `openfin8_eu`.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Row};
use utoipa::ToSchema;
use uuid::Uuid;

use openfin8_core::profile::Profile;
use sentin8::auth::client::AuthContext;
use sentin8::shield::{EvalTarget, PolicyEngine};

// ── The state machines (pure, unit-tested) ─────────────────────────────

/// The XS2A consent states (the four-state machine over the kernel's).
pub const CONSENT_RECEIVED: &str = "received";
pub const CONSENT_VALID: &str = "valid";
pub const CONSENT_REJECTED: &str = "rejected";
pub const CONSENT_EXPIRED: &str = "expired";
pub const CONSENT_REVOKED: &str = "revoked";

/// The authorisation sub-resource states (the per-approach machine).
pub const AUTH_RECEIVED: &str = "received";
pub const AUTH_PSU_IDENTIFIED: &str = "psu_identified";
pub const AUTH_PSU_AUTHENTICATED: &str = "psu_authenticated";
pub const AUTH_SCA_STARTED: &str = "sca_started";
pub const AUTH_FINALISED: &str = "finalised";
pub const AUTH_FAILED: &str = "failed";
pub const AUTH_EXPIRED: &str = "expired";

/// The SCA approaches (EU DESIGN.md §3 ceremony 3): redirect is
/// MANDATORY (always served); decoupled + embedded are conditional per
/// the RTS exemptions - the served list is honest per-environment
/// configuration and MUST always contain `redirect`.
pub const SCA_APPROACH_REDIRECT: &str = "redirect";
pub const SCA_APPROACH_DECOUPLED: &str = "decoupled";
pub const SCA_APPROACH_EMBEDDED: &str = "embedded";

/// The XS2A services a consent can be for.
pub const SERVICE_AIS: &str = "ais";
pub const SERVICE_PIS: &str = "pis";
pub const SERVICE_PIIS: &str = "piis";

/// The pure state-transition table for the consent machine. Returns the
/// target state, or `None` when the transition is illegal (a terminal
/// state never leaves; SCA success never bypasses the authorisation
/// observation - the caller drives transitions through the authorisation
/// outcome, never by asserting a target state directly).
pub fn consent_transition(from: &str, event: &str) -> Option<String> {
    match (from, event) {
        (_, "revoke") if from != CONSENT_REVOKED => Some(CONSENT_REVOKED.to_string()),
        (CONSENT_RECEIVED, "psu_denied") => Some(CONSENT_REJECTED.to_string()),
        (CONSENT_RECEIVED, "authorisation_finalised") => Some(CONSENT_VALID.to_string()),
        (CONSENT_RECEIVED | CONSENT_VALID, "expired") => Some(CONSENT_EXPIRED.to_string()),
        // A valid consent re-entering the ceremony (re-authorisation) stays
        // valid - the authorisation sub-resource is the ceremony's record,
        // not a consent demotion.
        (CONSENT_VALID, "authorisation_finalised") => Some(CONSENT_VALID.to_string()),
        _ => None,
    }
}

/// The pure state-transition table for an authorisation sub-resource's
/// per-approach machine. `failed` and `expired` are terminal for the
/// sub-resource (a new ceremony mints a NEW sub-resource; XS2A never
/// revives a finalised/denied ceremony).
pub fn authorisation_transition(from: &str, event: &str) -> Option<String> {
    match (from, event) {
        (AUTH_RECEIVED, "psu_identified") => Some(AUTH_PSU_IDENTIFIED.to_string()),
        (AUTH_RECEIVED | AUTH_PSU_IDENTIFIED, "psu_authenticated") => {
            Some(AUTH_PSU_AUTHENTICATED.to_string())
        }
        (AUTH_RECEIVED | AUTH_PSU_IDENTIFIED | AUTH_PSU_AUTHENTICATED, "sca_started") => {
            Some(AUTH_SCA_STARTED.to_string())
        }
        (
            AUTH_RECEIVED | AUTH_PSU_IDENTIFIED | AUTH_PSU_AUTHENTICATED | AUTH_SCA_STARTED,
            "sca_finalised",
        ) => Some(AUTH_FINALISED.to_string()),
        (
            AUTH_RECEIVED | AUTH_PSU_IDENTIFIED | AUTH_PSU_AUTHENTICATED | AUTH_SCA_STARTED,
            "sca_failed",
        ) => Some(AUTH_FAILED.to_string()),
        (
            AUTH_RECEIVED | AUTH_PSU_IDENTIFIED | AUTH_PSU_AUTHENTICATED | AUTH_SCA_STARTED,
            "expired",
        ) => Some(AUTH_EXPIRED.to_string()),
        _ => None,
    }
}

/// Validate an SCA approach selection against the served list. The list
/// MUST contain `redirect` (the mandatory approach); `embedded` is only
/// served where the RTS exemption rules allow (the adapter's
/// configuration is honest - EU DESIGN.md §7).
pub fn validate_served_approaches(served: &[&str]) -> Result<(), String> {
    if served.is_empty() {
        return Err("the served SCA approach list must not be empty".into());
    }
    if !served.contains(&SCA_APPROACH_REDIRECT) {
        return Err("redirect is the mandatory SCA approach and must always be served".into());
    }
    for a in served {
        if !matches!(
            *a,
            SCA_APPROACH_REDIRECT | SCA_APPROACH_DECOUPLED | SCA_APPROACH_EMBEDDED
        ) {
            return Err(format!("unknown SCA approach '{a}'"));
        }
    }
    Ok(())
}

/// Validate an approach selection for a NEW authorisation: it must be one
/// the deployment serves.
pub fn validate_approach_selection(approach: &str, served: &[&str]) -> Result<(), String> {
    if !served.contains(&approach) {
        return Err(format!(
            "SCA approach '{approach}' is not served by this deployment (served: {served:?})"
        ));
    }
    Ok(())
}

// ── Wire DTOs ──────────────────────────────────────────────────────────

/// `POST /v1/consents` request - the XS2A consent creation.
#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateConsentRequest {
    /// The PSU (bank customer) the consent is for.
    #[serde(rename = "customerId")]
    pub customer_id: Uuid,
    /// The recipient (TPP) handle.
    #[serde(rename = "recipientId", default)]
    pub recipient_id: Option<String>,
    /// The XS2A service: `ais` | `pis` | `piis`.
    pub service: String,
    /// The requested OAuth scopes (`openfin8:eu:*` vocabulary).
    #[serde(default)]
    pub scopes: Vec<String>,
    /// AIS: the max access frequency per day (absent = one-shot).
    #[serde(rename = "frequencyPerDay", default)]
    pub frequency_per_day: Option<i32>,
    /// AIS: the transaction lookback window (days from grant).
    #[serde(rename = "lookbackDays", default)]
    pub lookback_days: Option<i32>,
    /// The consent's validity window (absent = no expiry; XS2A caps AIS
    /// at 90 days).
    #[serde(rename = "expiresInDays", default)]
    pub expires_in_days: Option<i32>,
}

/// The XS2A consent document (wire shape).
#[derive(Debug, Serialize, ToSchema)]
pub struct ConsentResponse {
    /// The consent id.
    #[serde(rename = "consentId")]
    pub consent_id: Uuid,
    /// The PSU the consent belongs to.
    #[serde(rename = "customerId")]
    pub customer_id: Uuid,
    /// The XS2A service (`ais` | `pis` | `piis`).
    pub service: String,
    /// The four-state XS2A consent status.
    pub status: String,
    /// The requested scopes.
    pub scopes: Vec<String>,
    /// AIS frequency per day (absent for one-shot access).
    #[serde(rename = "frequencyPerDay", skip_serializing_if = "Option::is_none")]
    pub frequency_per_day: Option<i32>,
    /// AIS transaction lookback (days).
    #[serde(rename = "lookbackDays", skip_serializing_if = "Option::is_none")]
    pub lookback_days: Option<i32>,
    /// Expiry (absent for unlimited consents).
    #[serde(rename = "expiresAt", skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Creation timestamp.
    #[serde(rename = "createdAt")]
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// The pre-step request: `POST /v1/consents/{id}/authorisations` -
/// start an authorisation sub-resource (optionally selecting the SCA
/// approach BEFORE the PSU ceremony begins - EU DESIGN.md §3 ceremony 4).
#[derive(Debug, Deserialize, ToSchema)]
pub struct StartAuthorisationRequest {
    /// The SCA approach for this ceremony (defaults to the mandatory
    /// `redirect`).
    #[serde(default)]
    pub approach: Option<String>,
}

/// An authorisation sub-resource document (wire shape).
#[derive(Debug, Serialize, ToSchema)]
pub struct AuthorisationResponse {
    /// The authorisation id.
    #[serde(rename = "authorisationId")]
    pub authorisation_id: Uuid,
    /// The parent consent id.
    #[serde(rename = "consentId")]
    pub consent_id: Uuid,
    /// The per-approach authorisation status.
    pub status: String,
    /// The SCA approach this ceremony runs.
    pub approach: String,
    /// The PSU identity once identified.
    #[serde(rename = "psuId", skip_serializing_if = "Option::is_none")]
    pub psu_id: Option<String>,
    /// The Flow execution driving the ceremony (absent until started).
    #[serde(rename = "flowExecutionId", skip_serializing_if = "Option::is_none")]
    pub flow_execution_id: Option<Uuid>,
    /// The ceremony's expiry.
    #[serde(rename = "expiresAt", skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Creation timestamp.
    #[serde(rename = "createdAt")]
    pub created_at: chrono::DateTime<chrono::Utc>,
}

// ── The AppState ───────────────────────────────────────────────────────

/// The EU adapter's application state: the kernel profile + the pool +
/// the Shield engine + the auth client (the real gate - steps 1-5) + the
/// proxy-lane transports + the served SCA approach list
/// (honest per-environment configuration, EU DESIGN.md §5).
#[derive(Clone)]
pub struct AppState {
    pub pool: sqlx::PgPool,
    pub profile: Profile,
    /// The shell-booted policy engine (step 5 - the ONLY gate); the
    /// shell hands every service the same Arc (the engine is the
    /// process-wide instance).
    pub policy: std::sync::Arc<PolicyEngine>,
    /// The shared auth client (steps 1-4: discovery + JWKS caches).
    pub auth_client: sentin8::auth::client::Client,
    /// The platform issuer (bearer verification).
    pub auth_issuer: String,
    /// The Ledger proxy transport (workload `openfin8-eu-ledger`;
    /// None until the boot mint - the proxy lanes 503 loudly).
    pub ledger_http: Option<reqwest::Client>,
    /// The Ledger base URL.
    pub ledger_url: String,
    /// The Payments proxy transport (workload `openfin8-eu-payments`).
    pub payments_http: Option<reqwest::Client>,
    /// The Payments base URL.
    pub payments_url: String,
    /// The eIDAS configuration state: true when all four QSEALC/QWAC
    /// secret references are configured.
    pub eidas_configured: bool,
    /// The served openFinance version (from the profile).
    pub of_version: String,
    /// The served SCA approaches (redirect always present).
    pub served_approaches: Vec<String>,
    /// The request-scoped env id (resolved at the gate; the RLS context
    /// stamp uses it).
    env_id_cell: std::sync::Arc<std::sync::OnceLock<uuid::Uuid>>,
}

impl AppState {
    /// Build the state from the shell core + the boot-built lanes; the
    /// served-approach list comes from `OPENFIN8_EU_SCA_APPROACHES`
    /// (comma-separated; default `redirect` - the conservative start
    /// per EU DESIGN.md §8's embedded-SCA decision: decoupled +
    /// embedded are opt-in).
    pub fn from_core(
        core: sentin8::shell::ServiceCore,
        profile: Profile,
        ledger_http: Option<reqwest::Client>,
        ledger_url: String,
        payments_http: Option<reqwest::Client>,
        payments_url: String,
        eidas_configured: bool,
    ) -> Self {
        let raw = profile
            .env("SCA_APPROACHES")
            .unwrap_or_else(|| SCA_APPROACH_REDIRECT.to_string());
        let served: Vec<String> = raw
            .split(',')
            .map(|s| s.trim().to_ascii_lowercase())
            .filter(|s| !s.is_empty())
            .collect();
        // The honest list: redirect is mandatory - a configuration that
        // omits it is corrected loudly at boot, never silently served
        // without it.
        let mut served = served;
        if !served.iter().any(|a| a == SCA_APPROACH_REDIRECT) {
            tracing::warn!(
                "OPENFIN8_EU_SCA_APPROACHES omitted the mandatory 'redirect' - serving it anyway"
            );
            served.insert(0, SCA_APPROACH_REDIRECT.to_string());
        }
        let refs: Vec<&str> = served.iter().map(String::as_str).collect();
        if let Err(e) = validate_served_approaches(&refs) {
            tracing::warn!(
                "served SCA approach list invalid ({e}) - falling back to redirect-only"
            );
            served = vec![SCA_APPROACH_REDIRECT.to_string()];
        }
        Self {
            pool: core.pool.clone(),
            policy: core.admin.policy.clone(),
            auth_client: core.config.sentin8_auth_client.clone(),
            auth_issuer: core.config.sentin8_auth_issuer.clone(),
            ledger_http,
            ledger_url,
            payments_http,
            payments_url,
            eidas_configured,
            of_version: profile.fdx_version.clone(),
            served_approaches: served,
            env_id_cell: std::sync::Arc::new(std::sync::OnceLock::new()),
            profile,
        }
    }

    /// The eIDAS configuration state (PIS fails closed when false).
    pub fn eids_configured(&self) -> bool {
        self.eidas_configured
    }

    /// The Ledger proxy transport (None until the boot mint - the proxy
    /// lanes 503 loudly, never degrading to an unauthenticated call).
    pub fn ledger_http(&self) -> Option<&reqwest::Client> {
        self.ledger_http.as_ref()
    }

    /// The Payments proxy transport.
    pub fn payments_http(&self) -> Option<&reqwest::Client> {
        self.payments_http.as_ref()
    }

    /// The request-scoped env id (the Shield gate resolves the caller's
    /// env; the handlers' RLS context stamp reads it). Resolved once
    /// per state value (the shell hands each request a cloned state).
    pub fn env_id(&self) -> Uuid {
        *self.env_id_cell.get_or_init(Uuid::nil)
    }

    /// The Shield gate (the full contract - steps 1-5): verify the
    /// bearer (steps 1-4) + evaluate the action (step 5, the ONLY
    /// authorization decision; an enforced deny → 403).
    pub async fn authorize(
        &self,
        headers: &axum::http::HeaderMap,
        resource_action: &str,
    ) -> Result<AuthContext, (StatusCode, String)> {
        let a = sentin8::auth::client::verify_bearer_token(&self.auth_client, headers).await?;
        let target = EvalTarget::new(format!("{}:{}", self.profile.service_type, resource_action));
        sentin8::shield::runtime::require_policy(&self.policy, &a, headers, target).await?;
        let _ = self.env_id_cell.set(a.env_id());
        stamp_env_id(a.env_id());
        Ok(a)
    }
}

/// The Shield gate for the resource modules (ais/payments/ceremony):
/// verify + evaluate, returning the auth context or the 401/403.
pub async fn authorize(
    state: &AppState,
    headers: &axum::http::HeaderMap,
    resource_action: &str,
) -> Result<AuthContext, (StatusCode, String)> {
    state.authorize(headers, resource_action).await
}

// ── The emit path (the outbox contract, same-tx as the domain change) ──

/// Set the transaction-local RLS tenant context on the domain
/// transaction (the same contract openfin8-core's `common.rs` uses;
/// the stream-family arg is `openfin8-eu`). MUST run on the same
/// connection as the domain statements.
async fn set_tenant_context(conn: &mut sqlx::PgConnection, env_id: Uuid) {
    let _ = sqlx::query(
        "SELECT sentin8_set_tenant_context($1, NULL, NULL, NULL, false, false, false, NULL, 'openfin8-eu')",
    )
    .bind(env_id)
    .execute(conn)
    .await;
}

/// The pub re-export the resource modules (payments/ais/ceremony) use -
/// the same transaction-local contract.
pub async fn set_tenant_context_pub(conn: &mut sqlx::PgConnection, env_id: Uuid) {
    set_tenant_context(conn, env_id).await
}

/// Emit a bus event through the local outbox ON THE DOMAIN TRANSACTION
/// (the platform contract: `insert_outbox_row` in the SAME transaction as
/// the domain change - outbox-first, commits atomically). Stream family
/// `openfin8-eu`; event grammar `openfin8:eu:*`.
async fn emit_event(
    conn: &mut sqlx::PgConnection,
    env_id: Uuid,
    resource_operation: &str,
    payload: serde_json::Value,
) -> Result<(), sqlx::Error> {
    emit_event_pub(conn, env_id, resource_operation, payload).await
}

/// The pub re-export the resource modules use.
pub async fn emit_event_pub(
    conn: &mut sqlx::PgConnection,
    env_id: Uuid,
    resource_operation: &str,
    payload: serde_json::Value,
) -> Result<(), sqlx::Error> {
    sentin8::bus::outbox::insert_outbox_row(
        &mut *conn,
        env_id,
        "openfin8-eu",
        &format!("openfin8:eu:{resource_operation}"),
        &payload,
    )
    .await
    .map(|_| ())
    .map_err(|e| match e {
        sentin8::bus::outbox::OutboxError::Db(db) => db,
        other => sqlx::Error::Protocol(format!("outbox insert: {other}")),
    })
}

// ── The Consent API routes (XS2A, adapter-owned) ────────────────────────

/// `POST /v1/consents` - create an XS2A consent (the `received` state;
/// the PSU ceremony has not begun).
#[utoipa::path(
    post,
    path = "/v1/consents",
    request_body = CreateConsentRequest,
    responses(
        (status = 201, description = "Consent created (status received)", body = ConsentResponse),
        (status = 400, description = "Invalid service/scopes"),
        (status = 401, description = "Not authenticated"),
    ),
    security(),
    tag = "consent",
)]
pub async fn create_consent(
    State(state): State<AppState>,
    Json(req): Json<CreateConsentRequest>,
) -> Result<(StatusCode, Json<ConsentResponse>), (StatusCode, String)> {
    if !matches!(
        req.service.as_str(),
        SERVICE_AIS | SERVICE_PIS | SERVICE_PIIS
    ) {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "invalid service '{}' (allowed: ais, pis, piis)",
                req.service
            ),
        ));
    }
    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    set_tenant_context(&mut tx, uuid_env()).await;
    let expires_at = req
        .expires_in_days
        .map(|d| chrono::Utc::now() + chrono::Duration::days(d.min(90) as i64));
    let row = sqlx::query(
        r#"INSERT INTO openfin8_eu.consents
               (env_id, customer_id, recipient_id, status, service, scopes,
                frequency_per_day, lookback_days, expires_at)
           VALUES ($1, $2, $3, 'received', $4, $5, $6, $7, $8)
           RETURNING id, customer_id, service, status, scopes, frequency_per_day,
                     lookback_days, expires_at, created_at"#,
    )
    .bind(uuid_env())
    .bind(req.customer_id)
    .bind(req.recipient_id.as_deref())
    .bind(&req.service)
    .bind(&req.scopes)
    .bind(req.frequency_per_day)
    .bind(req.lookback_days)
    .bind(expires_at)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let consent_id: Uuid = row.get("id");
    emit_event(
        &mut tx,
        uuid_env(),
        "consent:created",
        serde_json::json!({ "consent_id": consent_id, "service": req.service, "status": "received" }),
    )
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    tx.commit()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok((
        StatusCode::CREATED,
        Json(ConsentResponse {
            consent_id,
            customer_id: row.get("customer_id"),
            service: row.get("service"),
            status: row.get("status"),
            scopes: row.get("scopes"),
            frequency_per_day: row.get("frequency_per_day"),
            lookback_days: row.get("lookback_days"),
            expires_at: row.get("expires_at"),
            created_at: row.get("created_at"),
        }),
    ))
}

/// `GET /v1/consents/{id}` - consent detail (the four-state status).
#[utoipa::path(
    get,
    path = "/v1/consents/{id}",
    responses(
        (status = 200, description = "Consent detail", body = ConsentResponse),
        (status = 404, description = "Unknown consent"),
    ),
    security(),
    tag = "consent",
)]
pub async fn get_consent(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<ConsentResponse>, (StatusCode, String)> {
    let mut conn = state
        .pool
        .acquire()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let row = sqlx::query(
        r#"SELECT id, customer_id, service, status, scopes, frequency_per_day,
                  lookback_days, expires_at, created_at
             FROM openfin8_eu.consents WHERE id = $1"#,
    )
    .bind(id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .ok_or((StatusCode::NOT_FOUND, "unknown consent".to_string()))?;
    Ok(Json(ConsentResponse {
        consent_id: row.get("id"),
        customer_id: row.get("customer_id"),
        service: row.get("service"),
        status: row.get("status"),
        scopes: row.get("scopes"),
        frequency_per_day: row.get("frequency_per_day"),
        lookback_days: row.get("lookback_days"),
        expires_at: row.get("expires_at"),
        created_at: row.get("created_at"),
    }))
}

/// `GET /v1/consents/{id}/status` - the XS2A consent status resource
/// (the four-state machine view).
#[derive(Debug, Serialize, ToSchema)]
pub struct ConsentStatusResponse {
    /// The consent id.
    #[serde(rename = "consentId")]
    pub consent_id: Uuid,
    /// The four-state XS2A status.
    pub status: String,
}

#[utoipa::path(
    get,
    path = "/v1/consents/{id}/status",
    responses(
        (status = 200, description = "Consent status", body = ConsentStatusResponse),
        (status = 404, description = "Unknown consent"),
    ),
    security(),
    tag = "consent",
)]
pub async fn get_consent_status(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<ConsentStatusResponse>, (StatusCode, String)> {
    let mut conn = state
        .pool
        .acquire()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let row = sqlx::query("SELECT status FROM openfin8_eu.consents WHERE id = $1")
        .bind(id)
        .fetch_optional(&mut *conn)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((StatusCode::NOT_FOUND, "unknown consent".to_string()))?;
    Ok(Json(ConsentStatusResponse {
        consent_id: id,
        status: row.get("status"),
    }))
}

/// `POST /v1/consents/{id}/authorisations` - the pre-step: create an
/// authorisation sub-resource (each SCA ceremony is its own object),
/// optionally selecting the SCA approach BEFORE the PSU ceremony begins.
#[utoipa::path(
    post,
    path = "/v1/consents/{id}/authorisations",
    request_body = StartAuthorisationRequest,
    responses(
        (status = 201, description = "Authorisation sub-resource created", body = AuthorisationResponse),
        (status = 400, description = "Approach not served by this deployment"),
        (status = 404, description = "Unknown consent"),
    ),
    security(),
    tag = "consent",
)]
pub async fn start_authorisation(
    State(state): State<AppState>,
    Path(consent_id): Path<Uuid>,
    Json(req): Json<StartAuthorisationRequest>,
) -> Result<(StatusCode, Json<AuthorisationResponse>), (StatusCode, String)> {
    // The approach selection is validated against the SERVED list - the
    // honest configuration (an unserved approach is a 400, never a
    // silent fallback).
    let approach = req
        .approach
        .unwrap_or_else(|| SCA_APPROACH_REDIRECT.to_string());
    let served: Vec<&str> = state.served_approaches.iter().map(String::as_str).collect();
    validate_approach_selection(&approach, &served).map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    set_tenant_context(&mut tx, uuid_env()).await;
    // The consent must exist and not be terminal (XS2A: a rejected/expired/
    // revoked consent cannot start a new ceremony).
    let consent_status: String =
        sqlx::query_scalar("SELECT status FROM openfin8_eu.consents WHERE id = $1 FOR SHARE")
            .bind(consent_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
            .ok_or((StatusCode::NOT_FOUND, "unknown consent".to_string()))?;
    if matches!(
        consent_status.as_str(),
        CONSENT_REJECTED | CONSENT_EXPIRED | CONSENT_REVOKED
    ) {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("consent is terminal ({consent_status}) - no new authorisation"),
        ));
    }
    let row = sqlx::query(
        r#"INSERT INTO openfin8_eu.consent_authorisations
               (env_id, consent_id, status, approach, expires_at)
           VALUES ($1, $2, 'received', $3, now() + interval '10 minutes')
           RETURNING id, consent_id, status, approach, psu_id, flow_execution_id, expires_at, created_at"#,
    )
    .bind(uuid_env())
    .bind(consent_id)
    .bind(&approach)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let authorisation_id: Uuid = row.get("id");
    emit_event(
        &mut tx,
        uuid_env(),
        "authorisation:started",
        serde_json::json!({
            "authorisation_id": authorisation_id,
            "consent_id": consent_id,
            "approach": approach,
            "status": "received"
        }),
    )
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    tx.commit()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok((
        StatusCode::CREATED,
        Json(AuthorisationResponse {
            authorisation_id,
            consent_id: row.get("consent_id"),
            status: row.get("status"),
            approach: row.get("approach"),
            psu_id: row.get("psu_id"),
            flow_execution_id: row.get("flow_execution_id"),
            expires_at: row.get("expires_at"),
            created_at: row.get("created_at"),
        }),
    ))
}

/// `GET /v1/consents/{id}/authorisations` - list the consent's
/// authorisation sub-resources (the TPP polls these under decoupled SCA).
#[derive(Debug, Serialize, ToSchema)]
pub struct AuthorisationListResponse {
    /// The consent's authorisation sub-resources.
    #[serde(rename = "authorisations")]
    pub authorisations: Vec<AuthorisationResponse>,
}

#[utoipa::path(
    get,
    path = "/v1/consents/{id}/authorisations",
    responses(
        (status = 200, description = "Authorisation list", body = AuthorisationListResponse),
        (status = 404, description = "Unknown consent"),
    ),
    security(),
    tag = "consent",
)]
pub async fn list_authorisations(
    State(state): State<AppState>,
    Path(consent_id): Path<Uuid>,
) -> Result<Json<AuthorisationListResponse>, (StatusCode, String)> {
    let mut conn = state
        .pool
        .acquire()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let rows = sqlx::query(
        r#"SELECT id, consent_id, status, approach, psu_id, flow_execution_id, expires_at, created_at
             FROM openfin8_eu.consent_authorisations
            WHERE consent_id = $1 ORDER BY created_at"#,
    )
    .bind(consent_id)
    .fetch_all(&mut *conn)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(AuthorisationListResponse {
        authorisations: rows
            .iter()
            .map(|row| AuthorisationResponse {
                authorisation_id: row.get("id"),
                consent_id: row.get("consent_id"),
                status: row.get("status"),
                approach: row.get("approach"),
                psu_id: row.get("psu_id"),
                flow_execution_id: row.get("flow_execution_id"),
                expires_at: row.get("expires_at"),
                created_at: row.get("created_at"),
            })
            .collect(),
    }))
}

/// `GET /v1/consents/{id}/authorisations/{authId}` - one authorisation
/// sub-resource (the decoupled-SCA poll target).
#[utoipa::path(
    get,
    path = "/v1/consents/{id}/authorisations/{authorisationId}",
    responses(
        (status = 200, description = "Authorisation detail", body = AuthorisationResponse),
        (status = 404, description = "Unknown authorisation"),
    ),
    security(),
    tag = "consent",
)]
pub async fn get_authorisation(
    State(state): State<AppState>,
    Path((_consent_id, authorisation_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<AuthorisationResponse>, (StatusCode, String)> {
    let mut conn = state
        .pool
        .acquire()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let row = sqlx::query(
        r#"SELECT id, consent_id, status, approach, psu_id, flow_execution_id, expires_at, created_at
             FROM openfin8_eu.consent_authorisations WHERE id = $1"#,
    )
    .bind(authorisation_id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .ok_or((StatusCode::NOT_FOUND, "unknown authorisation".to_string()))?;
    Ok(Json(AuthorisationResponse {
        authorisation_id: row.get("id"),
        consent_id: row.get("consent_id"),
        status: row.get("status"),
        approach: row.get("approach"),
        psu_id: row.get("psu_id"),
        flow_execution_id: row.get("flow_execution_id"),
        expires_at: row.get("expires_at"),
        created_at: row.get("created_at"),
    }))
}

/// Apply an authorisation outcome to the CONSENT (the observation path -
/// SCA success never conflated with the grant): `sca_finalised` on the
/// sub-resource drives the consent to `valid` via the pure table;
/// `sca_failed` with the PSU's explicit deny drives `rejected`.
pub async fn observe_authorisation_outcome(
    pool: &PgPool,
    consent_id: Uuid,
    authorisation_id: Uuid,
    event: &str,
) -> Result<String, (StatusCode, String)> {
    let mut tx = pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    set_tenant_context(&mut tx, uuid_env()).await;
    // The authorisation's own machine transition first.
    let auth_status: String = sqlx::query_scalar(
        "SELECT status FROM openfin8_eu.consent_authorisations WHERE id = $1 FOR UPDATE",
    )
    .bind(authorisation_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .ok_or((StatusCode::NOT_FOUND, "unknown authorisation".to_string()))?;
    let next_auth = authorisation_transition(&auth_status, event).ok_or((
        StatusCode::CONFLICT,
        format!("illegal authorisation transition: {auth_status} + {event}"),
    ))?;
    sqlx::query("UPDATE openfin8_eu.consent_authorisations SET status = $2, updated_at = now() WHERE id = $1")
        .bind(authorisation_id)
        .bind(&next_auth)
        .execute(&mut *tx)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    // The consent observes the outcome (never SCA-success == grant):
    // `sca_finalised` -> the PSU ceremony completed -> the consent goes
    // valid (or stays valid on re-authorisation); `sca_failed` does NOT
    // reject the consent (a failed challenge is retryable with a NEW
    // sub-resource) - only the PSU's explicit deny does.
    let consent_status: String =
        sqlx::query_scalar("SELECT status FROM openfin8_eu.consents WHERE id = $1 FOR UPDATE")
            .bind(consent_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
            .ok_or((StatusCode::NOT_FOUND, "unknown consent".to_string()))?;
    let consent_event = match event {
        "sca_finalised" => "authorisation_finalised",
        "psu_denied" => "psu_denied",
        _ => return Err((StatusCode::BAD_REQUEST, format!("unobserved event {event}"))),
    };
    let next_consent = consent_transition(&consent_status, consent_event).ok_or((
        StatusCode::CONFLICT,
        format!("illegal consent transition: {consent_status} + {consent_event}"),
    ))?;
    sqlx::query("UPDATE openfin8_eu.consents SET status = $2, updated_at = now() WHERE id = $1")
        .bind(consent_id)
        .bind(&next_consent)
        .execute(&mut *tx)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    emit_event(
        &mut tx,
        uuid_env(),
        &format!("authorisation:{event}"),
        serde_json::json!({
            "consent_id": consent_id,
            "authorisation_id": authorisation_id,
            "authorisation_status": next_auth,
            "consent_status": next_consent
        }),
    )
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    tx.commit()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(next_consent)
}

/// The request-scoped env id: the Shield gate's resolution (the
/// caller's env claim - the gate ran before any handler reaches this).
/// Falls back to nil only on the ungated paths (the RLS policies
/// enforce env scoping regardless - a nil stamp matches nothing).
fn uuid_env() -> Uuid {
    ENV_ID.with(|c| c.get())
}

thread_local! {
    /// The request-scoped env id (the gate stamps it before the handler
    /// runs; axum handlers run on the request's task thread).
    static ENV_ID: std::cell::Cell<Uuid> = const { std::cell::Cell::new(Uuid::nil()) };
}

/// Stamp the request-scoped env id (the gate calls this; the handler's
/// `uuid_env()` reads it on the same request thread).
pub fn stamp_env_id(env_id: Uuid) {
    ENV_ID.with(|c| c.set(env_id));
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn consent_machine_is_four_state_over_kernel() {
        // received -> valid via the authorisation observation.
        assert_eq!(
            consent_transition(CONSENT_RECEIVED, "authorisation_finalised").unwrap(),
            CONSENT_VALID
        );
        // received -> rejected on the PSU's deny.
        assert_eq!(
            consent_transition(CONSENT_RECEIVED, "psu_denied").unwrap(),
            CONSENT_REJECTED
        );
        // received/valid -> expired.
        assert_eq!(
            consent_transition(CONSENT_RECEIVED, "expired").unwrap(),
            CONSENT_EXPIRED
        );
        assert_eq!(
            consent_transition(CONSENT_VALID, "expired").unwrap(),
            CONSENT_EXPIRED
        );
        // revocation is terminal from any non-revoked state.
        assert_eq!(
            consent_transition(CONSENT_RECEIVED, "revoke").unwrap(),
            CONSENT_REVOKED
        );
        assert_eq!(
            consent_transition(CONSENT_VALID, "revoke").unwrap(),
            CONSENT_REVOKED
        );
        // terminal states never leave.
        assert_eq!(
            consent_transition(CONSENT_REVOKED, "authorisation_finalised"),
            None
        );
        assert_eq!(
            consent_transition(CONSENT_EXPIRED, "authorisation_finalised"),
            None
        );
        assert_eq!(
            consent_transition(CONSENT_REJECTED, "authorisation_finalised"),
            None
        );
        // SCA success never bypasses the observation path.
        assert_eq!(consent_transition(CONSENT_RECEIVED, "sca_finalised"), None);
    }

    #[test]
    fn authorisation_machine_is_per_approach() {
        // the full happy path.
        assert_eq!(
            authorisation_transition(AUTH_RECEIVED, "psu_identified").unwrap(),
            AUTH_PSU_IDENTIFIED
        );
        assert_eq!(
            authorisation_transition(AUTH_PSU_IDENTIFIED, "psu_authenticated").unwrap(),
            AUTH_PSU_AUTHENTICATED
        );
        assert_eq!(
            authorisation_transition(AUTH_PSU_AUTHENTICATED, "sca_started").unwrap(),
            AUTH_SCA_STARTED
        );
        assert_eq!(
            authorisation_transition(AUTH_SCA_STARTED, "sca_finalised").unwrap(),
            AUTH_FINALISED
        );
        // decoupled/embedded ride the same machine (the approach selects
        // the ceremony, not different states).
        assert_eq!(
            authorisation_transition(AUTH_RECEIVED, "sca_finalised").unwrap(),
            AUTH_FINALISED
        );
        // failure + expiry are terminal for the sub-resource.
        assert_eq!(
            authorisation_transition(AUTH_SCA_STARTED, "sca_failed").unwrap(),
            AUTH_FAILED
        );
        assert_eq!(authorisation_transition(AUTH_FAILED, "sca_finalised"), None);
        assert_eq!(
            authorisation_transition(AUTH_RECEIVED, "expired").unwrap(),
            AUTH_EXPIRED
        );
        assert_eq!(
            authorisation_transition(AUTH_EXPIRED, "sca_finalised"),
            None
        );
        // finalised is terminal (a new ceremony mints a new sub-resource).
        assert_eq!(authorisation_transition(AUTH_FINALISED, "sca_failed"), None);
    }

    #[test]
    fn served_approaches_always_contain_redirect() {
        // empty list rejected.
        assert!(validate_served_approaches(&[]).is_err());
        // redirect-only is the conservative default.
        assert!(validate_served_approaches(&[SCA_APPROACH_REDIRECT]).is_ok());
        // all three approaches served.
        assert!(validate_served_approaches(&[
            SCA_APPROACH_REDIRECT,
            SCA_APPROACH_DECOUPLED,
            SCA_APPROACH_EMBEDDED
        ])
        .is_ok());
        // omitting redirect is invalid (mandatory).
        assert!(validate_served_approaches(&[SCA_APPROACH_DECOUPLED]).is_err());
        // unknown approach rejected.
        assert!(validate_served_approaches(&[SCA_APPROACH_REDIRECT, "carrier-pigeon"]).is_err());
        // selection against the served list.
        assert!(validate_approach_selection("redirect", &[SCA_APPROACH_REDIRECT]).is_ok());
        assert!(validate_approach_selection("embedded", &[SCA_APPROACH_REDIRECT]).is_err());
    }
}
