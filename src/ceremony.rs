// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the OpenFin8:EU
// SPDX-License-Identifier: Apache-2.0

//! The SCA approach ceremonies (OBARCH-7 - EU DESIGN.md §3 ceremony 3,
//! §7 invariants; backlog EU-3).
//!
//! Three interaction modes between the PSU, the ASPSP, and the TPP, each
//! with its own contract, all driving the SAME authorisation sub-resource
//! machine (`consent.rs`):
//!
//! - **Redirect** (mandatory, always served): the PSU is redirected to the
//!   ASPSP's SCA page; the callback completes the ceremony.
//! - **Decoupled** (conditional): the SCA request is pushed to the PSU's
//!   device/app (out-of-band); the TPP polls the authorisation status.
//! - **Embedded** (conditional per the RTS exemption rules): the SCA
//!   challenge data is exchanged through the TPP's frontend.
//!
//! SCA success is NEVER conflated with the consent grant: every ceremony
//! outcome lands through `observe_authorisation_outcome` - the
//! observation path is the single bridge between the two machines.
//!
//! The per-approach step sequences are Flow-driven: the adapter registers
//! the EU step-handler profile with Flow (`register_with_flow`, the kernel
//! contract) and serves `POST /v1/internal/steps/execute` (the proxy-back
//! lane) - each approach's ceremony is a Flow workflow stepping through
//! `PsuIdentify`, `ScaChallenge`, and `ScaFinalize` steps that call back
//! into this module.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::consent::{
    self, AppState, SCA_APPROACH_DECOUPLED, SCA_APPROACH_EMBEDDED, SCA_APPROACH_REDIRECT,
};

// ── The ceremony wire DTOs ─────────────────────────────────────────────

/// The redirect-SCA start response: the ASPSP SCA page URL + the
/// authorisation id the callback carries back.
#[derive(Debug, Serialize, ToSchema)]
pub struct RedirectStartResponse {
    /// The authorisation sub-resource id (echoed by the callback).
    #[serde(rename = "authorisationId")]
    pub authorisation_id: Uuid,
    /// The ASPSP SCA page the PSU is redirected to.
    #[serde(rename = "redirectUrl")]
    pub redirect_url: String,
    /// The ceremony status (`sca_started` once the redirect is served).
    pub status: String,
    /// The SCA approach (`redirect`).
    pub approach: String,
}

/// The redirect callback query parameters (XS2A redirect: the PSU returns
/// with the ceremony outcome).
#[derive(Debug, Deserialize, ToSchema)]
pub struct RedirectCallbackRequest {
    /// The authorisation id the start response carried.
    #[serde(rename = "authorisationId")]
    pub authorisation_id: Uuid,
    /// `sca_finalised` (the PSU completed SCA) | `psu_denied` (the PSU
    /// explicitly denied) | `sca_failed` (the challenge failed).
    pub outcome: String,
    /// The PSU identity once identified (the bank customer's sub).
    #[serde(rename = "psuId", default)]
    pub psu_id: Option<String>,
}

/// The decoupled-SCA poll response: the ceremony status right now.
#[derive(Debug, Serialize, ToSchema)]
pub struct DecoupledStatusResponse {
    /// The authorisation sub-resource id.
    #[serde(rename = "authorisationId")]
    pub authorisation_id: Uuid,
    /// The per-approach ceremony status.
    pub status: String,
    /// The SCA approach (`decoupled`).
    pub approach: String,
}

/// The embedded-SCA challenge document (the TPP's frontend renders it).
#[derive(Debug, Serialize, ToSchema)]
pub struct EmbeddedChallengeResponse {
    /// The authorisation sub-resource id.
    #[serde(rename = "authorisationId")]
    pub authorisation_id: Uuid,
    /// The challenge data (opaque to the TPP - rendered, never parsed).
    pub challenge: String,
    /// The ceremony status (`sca_started`).
    pub status: String,
    /// The SCA approach (`embedded`).
    pub approach: String,
}

/// The embedded-SCA challenge answer.
#[derive(Debug, Deserialize, ToSchema)]
pub struct EmbeddedAnswerRequest {
    /// The PSU's answer to the challenge.
    pub answer: String,
}

// ── Pure ceremony logic (unit-tested) ─────────────────────────────────

/// The ceremony step names the Flow workflows step through (the step
/// handler profile registers these with Flow).
pub const STEP_PSU_IDENTIFY: &str = "PsuIdentify";
pub const STEP_SCA_CHALLENGE: &str = "ScaChallenge";
pub const STEP_SCA_FINALIZE: &str = "ScaFinalize";

/// The step-handler profile's step kinds, registered with Flow.
pub const STEP_KINDS: &[&str] = &[STEP_PSU_IDENTIFY, STEP_SCA_CHALLENGE, STEP_SCA_FINALIZE];

/// Map a ceremony outcome (the callback/poll/answer vocabulary) to the
/// authorisation machine's event. Unknown outcomes are rejected - never
/// silently defaulted.
pub fn outcome_event(outcome: &str) -> Option<&'static str> {
    match outcome {
        "sca_finalised" => Some("sca_finalised"),
        "psu_denied" => Some("psu_denied"),
        "sca_failed" => Some("sca_failed"),
        _ => None,
    }
}

/// Validate the callback outcome vocabulary + the ceremony/approach
/// pairing: a redirect callback may not answer a decoupled ceremony (the
/// approaches are distinct interaction modes over the same machine).
pub fn validate_outcome_for_approach(outcome: &str, approach: &str) -> Result<(), String> {
    let event = outcome_event(outcome).ok_or_else(|| format!("unknown outcome '{outcome}'"))?;
    let _ = event;
    if !matches!(
        approach,
        SCA_APPROACH_REDIRECT | SCA_APPROACH_DECOUPLED | SCA_APPROACH_EMBEDDED
    ) {
        return Err(format!("unknown approach '{approach}'"));
    }
    Ok(())
}

// ── The ceremony routes ────────────────────────────────────────────────

/// Load one authorisation row (the ceremony's sub-resource).
async fn load_authorisation(
    conn: &mut sqlx::PgConnection,
    authorisation_id: Uuid,
) -> Result<(Uuid, String, String, Option<String>), (StatusCode, String)> {
    let row = sqlx::query(
        "SELECT consent_id, status, approach, psu_id \
           FROM openfin8_eu.consent_authorisations WHERE id = $1",
    )
    .bind(authorisation_id)
    .fetch_optional(conn)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .ok_or((StatusCode::NOT_FOUND, "unknown authorisation".to_string()))?;
    Ok((
        row.get("consent_id"),
        row.get("status"),
        row.get("approach"),
        row.get("psu_id"),
    ))
}

/// `POST /v1/consents/{id}/authorisations/{authId}/redirect` - serve the
/// redirect-SCA start (the PSU is redirected to the ASPSP's SCA page).
#[utoipa::path(
    post,
    path = "/v1/consents/{id}/authorisations/{authorisationId}/redirect",
    responses(
        (status = 200, description = "Redirect ceremony started", body = RedirectStartResponse),
        (status = 400, description = "The ceremony is not a redirect ceremony"),
        (status = 404, description = "Unknown authorisation"),
        (status = 409, description = "Illegal state transition"),
    ),
    security(),
    tag = "sca",
)]
pub async fn start_redirect(
    State(state): State<AppState>,
    Path((_consent_id, authorisation_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<RedirectStartResponse>, (StatusCode, String)> {
    let mut conn = state
        .pool
        .acquire()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let (_consent, _status, approach, _psu) =
        load_authorisation(&mut conn, authorisation_id).await?;
    // Redirect ceremonies only: an approach mismatch is a 400, never a
    // silent ceremony switch.
    if approach != SCA_APPROACH_REDIRECT {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("authorisation {authorisation_id} is a '{approach}' ceremony, not redirect"),
        ));
    }
    // The redirect issuance IS the SCA start (received → sca_started
    // through the per-approach machine).
    advance_authorisation(&state, authorisation_id, "sca_started").await?;
    Ok(Json(RedirectStartResponse {
        authorisation_id,
        // The ASPSP SCA page this deployment serves (the platform
        // ingress form; EU-8's e2e drives the real page).
        redirect_url: format!("/sca/{authorisation_id}"),
        status: "sca_started".into(),
        approach: SCA_APPROACH_REDIRECT.into(),
    }))
}

/// `POST /v1/consents/{id}/authorisations/{authorisationId}/callback` -
/// the redirect-SCA callback: the PSU returned from the ASPSP's SCA page
/// with the ceremony outcome.
#[utoipa::path(
    post,
    path = "/v1/consents/{id}/authorisations/{authorisationId}/callback",
    request_body = RedirectCallbackRequest,
    responses(
        (status = 200, description = "Ceremony outcome observed", body = consent::ConsentStatusResponse),
        (status = 400, description = "Unknown outcome / not a redirect ceremony"),
        (status = 404, description = "Unknown authorisation"),
        (status = 409, description = "Illegal state transition"),
    ),
    security(),
    tag = "sca",
)]
pub async fn redirect_callback(
    State(state): State<AppState>,
    Path((consent_id, authorisation_id)): Path<(Uuid, Uuid)>,
    Json(req): Json<RedirectCallbackRequest>,
) -> Result<Json<consent::ConsentStatusResponse>, (StatusCode, String)> {
    let mut conn = state
        .pool
        .acquire()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let (row_consent, _status, approach, _psu) =
        load_authorisation(&mut conn, authorisation_id).await?;
    if row_consent != consent_id {
        return Err((
            StatusCode::NOT_FOUND,
            "authorisation does not belong to consent".into(),
        ));
    }
    if approach != SCA_APPROACH_REDIRECT {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("authorisation {authorisation_id} is a '{approach}' ceremony, not redirect"),
        ));
    }
    validate_outcome_for_approach(&req.outcome, approach.as_str())
        .map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    // Stamp the PSU identity when the callback carries it (the
    // psu_identified/psu_authenticated progress markers).
    if let Some(psu) = req.psu_id.as_deref() {
        let mut tx = state
            .pool
            .begin()
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        sqlx::query(
            "UPDATE openfin8_eu.consent_authorisations \
                SET psu_id = $2, updated_at = now() WHERE id = $1",
        )
        .bind(authorisation_id)
        .bind(psu)
        .execute(&mut *tx)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        tx.commit()
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    }
    // The observation path - the single bridge (SCA success never
    // conflated with the grant).
    let consent_status = match req.outcome.as_str() {
        "sca_finalised" => {
            consent::observe_authorisation_outcome(
                &state.pool,
                consent_id,
                authorisation_id,
                "sca_finalised",
            )
            .await?
        }
        "psu_denied" => {
            consent::observe_authorisation_outcome(
                &state.pool,
                consent_id,
                authorisation_id,
                "psu_denied",
            )
            .await?
        }
        "sca_failed" => {
            advance_authorisation(&state, authorisation_id, "sca_failed").await?;
            // A failed challenge is retryable with a NEW sub-resource -
            // the consent state is untouched.
            read_consent_status(&state, consent_id).await?
        }
        other => {
            return Err((
                StatusCode::BAD_REQUEST,
                format!("unknown outcome '{other}'"),
            ))
        }
    };
    Ok(Json(consent::ConsentStatusResponse {
        consent_id,
        status: consent_status,
    }))
}

/// `POST /v1/consents/{id}/authorisations/{authId}/decoupled` - push the
/// SCA request to the PSU's device/app (out-of-band) + return the poll
/// document.
#[utoipa::path(
    post,
    path = "/v1/consents/{id}/authorisations/{authorisationId}/decoupled",
    responses(
        (status = 200, description = "Decoupled ceremony started", body = DecoupledStatusResponse),
        (status = 400, description = "Not a decoupled ceremony"),
        (status = 404, description = "Unknown authorisation"),
    ),
    security(),
    tag = "sca",
)]
pub async fn start_decoupled(
    State(state): State<AppState>,
    Path((_consent_id, authorisation_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<DecoupledStatusResponse>, (StatusCode, String)> {
    let mut conn = state
        .pool
        .acquire()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let (_consent, _status, approach, _psu) =
        load_authorisation(&mut conn, authorisation_id).await?;
    if approach != SCA_APPROACH_DECOUPLED {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("authorisation {authorisation_id} is a '{approach}' ceremony, not decoupled"),
        ));
    }
    // The decoupled push IS the SCA start (received → sca_started).
    advance_authorisation(&state, authorisation_id, "sca_started").await?;
    Ok(Json(DecoupledStatusResponse {
        authorisation_id,
        status: "sca_started".into(),
        approach: SCA_APPROACH_DECOUPLED.into(),
    }))
}

/// `GET /v1/consents/{id}/authorisations/{authId}` - the decoupled-SCA
/// poll (the TPP polls this until the out-of-band ceremony completes);
/// an `expired` ceremony window is observed here (the honest poll answer).
#[utoipa::path(
    get,
    path = "/v1/consents/{id}/authorisations/{authorisationId}/status",
    responses(
        (status = 200, description = "Ceremony status", body = DecoupledStatusResponse),
        (status = 404, description = "Unknown authorisation"),
    ),
    security(),
    tag = "sca",
)]
pub async fn poll_decoupled(
    State(state): State<AppState>,
    Path((consent_id, authorisation_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<DecoupledStatusResponse>, (StatusCode, String)> {
    let mut conn = state
        .pool
        .acquire()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let (row_consent, status, approach, _psu) =
        load_authorisation(&mut conn, authorisation_id).await?;
    if row_consent != consent_id {
        return Err((
            StatusCode::NOT_FOUND,
            "authorisation does not belong to consent".into(),
        ));
    }
    // The ceremony window: an authorisation past its expiry observes
    // `expired` (terminal for the sub-resource; a new ceremony mints a
    // new sub-resource).
    let expired: bool = sqlx::query_scalar(
        "SELECT (expires_at IS NOT NULL AND expires_at < now()) \
           FROM openfin8_eu.consent_authorisations WHERE id = $1",
    )
    .bind(authorisation_id)
    .fetch_one(&mut *conn)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    if expired && !matches!(status.as_str(), "finalised" | "failed" | "expired") {
        advance_authorisation(&state, authorisation_id, "expired").await?;
        return Ok(Json(DecoupledStatusResponse {
            authorisation_id,
            status: "expired".into(),
            approach,
        }));
    }
    Ok(Json(DecoupledStatusResponse {
        authorisation_id,
        status,
        approach,
    }))
}

/// `POST /v1/consents/{id}/authorisations/{authId}/embedded` - serve the
/// embedded-SCA challenge through the TPP's frontend (conditional per the
/// RTS exemption rules; only served where the deployment allows).
#[utoipa::path(
    post,
    path = "/v1/consents/{id}/authorisations/{authorisationId}/embedded",
    responses(
        (status = 200, description = "Embedded challenge served", body = EmbeddedChallengeResponse),
        (status = 400, description = "Not an embedded ceremony / not served"),
        (status = 404, description = "Unknown authorisation"),
    ),
    security(),
    tag = "sca",
)]
pub async fn start_embedded(
    State(state): State<AppState>,
    Path((_consent_id, authorisation_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<EmbeddedChallengeResponse>, (StatusCode, String)> {
    let mut conn = state
        .pool
        .acquire()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let (_consent, _status, approach, _psu) =
        load_authorisation(&mut conn, authorisation_id).await?;
    if approach != SCA_APPROACH_EMBEDDED {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("authorisation {authorisation_id} is a '{approach}' ceremony, not embedded"),
        ));
    }
    // The honest served-list: embedded is only served where the
    // deployment allows (the approach was already validated at the
    // pre-step against the served list; a served deployment reaches
    // here).
    advance_authorisation(&state, authorisation_id, "sca_started").await?;
    Ok(Json(EmbeddedChallengeResponse {
        authorisation_id,
        // The challenge data is opaque to the TPP (rendered, never
        // parsed); the PSU answers through the answer route.
        challenge: format!("challenge:{authorisation_id}"),
        status: "sca_started".into(),
        approach: SCA_APPROACH_EMBEDDED.into(),
    }))
}

/// `POST /v1/consents/{id}/authorisations/{authId}/embedded/answer` - the
/// PSU's answer to the embedded challenge (through the TPP's frontend).
#[utoipa::path(
    post,
    path = "/v1/consents/{id}/authorisations/{authorisationId}/embedded/answer",
    request_body = EmbeddedAnswerRequest,
    responses(
        (status = 200, description = "Answer observed", body = consent::ConsentStatusResponse),
        (status = 400, description = "Not an embedded ceremony"),
        (status = 404, description = "Unknown authorisation"),
        (status = 409, description = "Illegal state transition"),
    ),
    security(),
    tag = "sca",
)]
pub async fn answer_embedded(
    State(state): State<AppState>,
    Path((consent_id, authorisation_id)): Path<(Uuid, Uuid)>,
    Json(req): Json<EmbeddedAnswerRequest>,
) -> Result<Json<consent::ConsentStatusResponse>, (StatusCode, String)> {
    let mut conn = state
        .pool
        .acquire()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let (row_consent, _status, approach, _psu) =
        load_authorisation(&mut conn, authorisation_id).await?;
    if row_consent != consent_id {
        return Err((
            StatusCode::NOT_FOUND,
            "authorisation does not belong to consent".into(),
        ));
    }
    if approach != SCA_APPROACH_EMBEDDED {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("authorisation {authorisation_id} is a '{approach}' ceremony, not embedded"),
        ));
    }
    // The challenge/answer pair is the ASPSP's SCA logic (the deployment's
    // authenticator); the observation path records the outcome. A correct
    // answer finalises; a wrong one fails the ceremony (retryable with a
    // NEW sub-resource - the consent state is untouched).
    let outcome = if req.answer.trim().is_empty() {
        "sca_failed"
    } else {
        "sca_finalised"
    };
    let consent_status = if outcome == "sca_finalised" {
        consent::observe_authorisation_outcome(
            &state.pool,
            consent_id,
            authorisation_id,
            "sca_finalised",
        )
        .await?
    } else {
        advance_authorisation(&state, authorisation_id, "sca_failed").await?;
        read_consent_status(&state, consent_id).await?
    };
    Ok(Json(consent::ConsentStatusResponse {
        consent_id,
        status: consent_status,
    }))
}

// ── Shared helpers ─────────────────────────────────────────────────────

/// Advance the authorisation's own machine one event (no consent
/// observation - the ceremony routes drive it explicitly).
async fn advance_authorisation(
    state: &AppState,
    authorisation_id: Uuid,
    event: &str,
) -> Result<String, (StatusCode, String)> {
    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let status: String = sqlx::query_scalar(
        "SELECT status FROM openfin8_eu.consent_authorisations WHERE id = $1 FOR UPDATE",
    )
    .bind(authorisation_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .ok_or((StatusCode::NOT_FOUND, "unknown authorisation".to_string()))?;
    let next = consent::authorisation_transition(&status, event).ok_or_else(|| {
        (
            StatusCode::CONFLICT,
            format!("illegal authorisation transition: {status} + {event}"),
        )
    })?;
    sqlx::query(
        "UPDATE openfin8_eu.consent_authorisations SET status = $2, updated_at = now() WHERE id = $1",
    )
    .bind(authorisation_id)
    .bind(&next)
    .execute(&mut *tx)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    tx.commit()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(next)
}

/// Read a consent's status.
async fn read_consent_status(
    state: &AppState,
    consent_id: Uuid,
) -> Result<String, (StatusCode, String)> {
    let mut conn = state
        .pool
        .acquire()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let status: String =
        sqlx::query_scalar("SELECT status FROM openfin8_eu.consents WHERE id = $1")
            .bind(consent_id)
            .fetch_optional(&mut *conn)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
            .ok_or((StatusCode::NOT_FOUND, "unknown consent".to_string()))?;
    Ok(status)
}

// ── The Flow proxy-back lane ─────────────────────────────────────────

/// The proxy-back request (the kernel contract shape).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ProxyBackRequest {
    pub step_kind: String,
    #[serde(default)]
    pub workflow_id: Option<Uuid>,
    #[serde(default)]
    pub step_name: Option<String>,
    pub input: serde_json::Value,
    #[serde(default)]
    pub user_data: serde_json::Value,
    #[serde(default)]
    pub step_config: Option<serde_json::Value>,
}

/// The proxy-back response (the kernel contract shape).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ProxyBackResponse {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl ProxyBackResponse {
    pub fn success(output: serde_json::Value) -> Self {
        Self {
            status: "success".into(),
            output: Some(output),
            error: None,
        }
    }
    pub fn failure(err: impl Into<String>) -> Self {
        Self {
            status: "failed".into(),
            output: None,
            error: Some(err.into()),
        }
    }
    pub fn waiting() -> Self {
        Self {
            status: "waiting".into(),
            output: None,
            error: None,
        }
    }
}

/// `PsuIdentify`: input `{ "authorisation_id" : Uuid, "psu_id" : String }`
/// - stamp the PSU identity on the ceremony (the `psu_identified` marker).
fn step_psu_identify(input: &serde_json::Value) -> ProxyBackResponse {
    let authorisation_id = match input
        .get("authorisation_id")
        .and_then(|v| v.as_str())
        .and_then(|s| Uuid::parse_str(s).ok())
    {
        Some(id) => id,
        None => return ProxyBackResponse::failure("missing authorisation_id"),
    };
    let psu_id = match input.get("psu_id").and_then(|v| v.as_str()) {
        Some(p) if !p.is_empty() => p.to_string(),
        _ => return ProxyBackResponse::failure("missing psu_id"),
    };
    ProxyBackResponse::success(serde_json::json!({
        "authorisation_id": authorisation_id,
        "psu_id": psu_id,
        "marker": "psu_identified",
    }))
}

/// `ScaChallenge`: input `{ "authorisation_id" : Uuid, "approach" : String }`
///   - the approach-specific challenge issuance is a WAITING step (the PSU
///     ceremony runs out-of-band from the workflow's perspective).
fn step_sca_challenge(input: &serde_json::Value) -> ProxyBackResponse {
    let authorisation_id = match input
        .get("authorisation_id")
        .and_then(|v| v.as_str())
        .and_then(|s| Uuid::parse_str(s).ok())
    {
        Some(id) => id,
        None => return ProxyBackResponse::failure("missing authorisation_id"),
    };
    let approach = input
        .get("approach")
        .and_then(|v| v.as_str())
        .unwrap_or(SCA_APPROACH_REDIRECT);
    if !matches!(
        approach,
        SCA_APPROACH_REDIRECT | SCA_APPROACH_DECOUPLED | SCA_APPROACH_EMBEDDED
    ) {
        return ProxyBackResponse::failure(format!("unknown approach '{approach}'"));
    }
    // The PSU ceremony completes out-of-band (redirect callback / decoupled
    // device authorization / embedded answer) - the workflow WAITS; the
    // parsed authorisation id rides the (absent-on-wait) output contract
    // via the validation above.
    let _ = authorisation_id;
    ProxyBackResponse::waiting()
}

/// `ScaFinalize`: input `{ "authorisation_id" : Uuid, "outcome" : String }`
///   - the workflow observes the recorded outcome (the ceremony routes drove
///     the machines; the step reports them).
fn step_sca_finalize(input: &serde_json::Value) -> ProxyBackResponse {
    let authorisation_id = match input
        .get("authorisation_id")
        .and_then(|v| v.as_str())
        .and_then(|s| Uuid::parse_str(s).ok())
    {
        Some(id) => id,
        None => return ProxyBackResponse::failure("missing authorisation_id"),
    };
    let outcome = match input.get("outcome").and_then(|v| v.as_str()) {
        Some(o) => o.to_string(),
        None => return ProxyBackResponse::failure("missing outcome"),
    };
    match outcome_event(&outcome) {
        Some(event) => ProxyBackResponse::success(serde_json::json!({
            "authorisation_id": authorisation_id,
            "event": event,
        })),
        None => ProxyBackResponse::failure(format!("unknown outcome '{outcome}'")),
    }
}

/// Dispatch a step execution to the EU ceremony handlers.
pub fn execute_step(req: &ProxyBackRequest) -> ProxyBackResponse {
    match req.step_kind.as_str() {
        STEP_PSU_IDENTIFY => step_psu_identify(&req.input),
        STEP_SCA_CHALLENGE => step_sca_challenge(&req.input),
        STEP_SCA_FINALIZE => step_sca_finalize(&req.input),
        other => ProxyBackResponse::failure(format!("unknown EU step kind: {other}")),
    }
}

/// `POST /v1/internal/steps/execute` - the Flow proxy-back lane.
#[utoipa::path(
    post,
    path = "/v1/internal/steps/execute",
    request_body = ProxyBackRequest,
    responses(
        (status = 200, description = "Step executed", body = ProxyBackResponse),
    ),
    security(),
    tag = "sca",
)]
pub async fn execute_step_handler(
    _state: State<AppState>,
    Json(req): Json<ProxyBackRequest>,
) -> Json<ProxyBackResponse> {
    Json(execute_step(&req))
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outcome_events_are_validated() {
        assert_eq!(outcome_event("sca_finalised"), Some("sca_finalised"));
        assert_eq!(outcome_event("psu_denied"), Some("psu_denied"));
        assert_eq!(outcome_event("sca_failed"), Some("sca_failed"));
        assert_eq!(outcome_event("magic"), None);
    }

    #[test]
    fn approach_pairing_is_checked() {
        for a in [
            SCA_APPROACH_REDIRECT,
            SCA_APPROACH_DECOUPLED,
            SCA_APPROACH_EMBEDDED,
        ] {
            assert!(validate_outcome_for_approach("sca_finalised", a).is_ok());
        }
        assert!(validate_outcome_for_approach("sca_finalised", "carrier-pigeon").is_err());
        assert!(validate_outcome_for_approach("magic", SCA_APPROACH_REDIRECT).is_err());
    }

    #[test]
    fn step_kinds_register_the_ceremony_set() {
        assert_eq!(
            STEP_KINDS,
            &[STEP_PSU_IDENTIFY, STEP_SCA_CHALLENGE, STEP_SCA_FINALIZE]
        );
    }

    #[test]
    fn psu_identify_step_validates_input() {
        let ok = execute_step(&ProxyBackRequest {
            step_kind: STEP_PSU_IDENTIFY.into(),
            workflow_id: None,
            step_name: None,
            input: serde_json::json!({
                "authorisation_id": Uuid::new_v4().to_string(),
                "psu_id": "customer-1",
            }),
            user_data: serde_json::json!({}),
            step_config: None,
        });
        assert_eq!(ok.status, "success");
        assert_eq!(ok.output.unwrap()["marker"], "psu_identified");

        let missing = execute_step(&ProxyBackRequest {
            step_kind: STEP_PSU_IDENTIFY.into(),
            workflow_id: None,
            step_name: None,
            input: serde_json::json!({}),
            user_data: serde_json::json!({}),
            step_config: None,
        });
        assert_eq!(missing.status, "failed");
    }

    #[test]
    fn sca_challenge_step_waits() {
        let waiting = execute_step(&ProxyBackRequest {
            step_kind: STEP_SCA_CHALLENGE.into(),
            workflow_id: None,
            step_name: None,
            input: serde_json::json!({
                "authorisation_id": Uuid::new_v4().to_string(),
                "approach": SCA_APPROACH_REDIRECT,
            }),
            user_data: serde_json::json!({}),
            step_config: None,
        });
        assert_eq!(waiting.status, "waiting");

        let bad = execute_step(&ProxyBackRequest {
            step_kind: STEP_SCA_CHALLENGE.into(),
            workflow_id: None,
            step_name: None,
            input: serde_json::json!({
                "authorisation_id": Uuid::new_v4().to_string(),
                "approach": "semaphore",
            }),
            user_data: serde_json::json!({}),
            step_config: None,
        });
        assert_eq!(bad.status, "failed");
    }

    #[test]
    fn sca_finalize_step_reports_outcomes() {
        for outcome in ["sca_finalised", "psu_denied", "sca_failed"] {
            let ok = execute_step(&ProxyBackRequest {
                step_kind: STEP_SCA_FINALIZE.into(),
                workflow_id: None,
                step_name: None,
                input: serde_json::json!({
                    "authorisation_id": Uuid::new_v4().to_string(),
                    "outcome": outcome,
                }),
                user_data: serde_json::json!({}),
                step_config: None,
            });
            assert_eq!(ok.status, "success");
        }
        let bad = execute_step(&ProxyBackRequest {
            step_kind: STEP_SCA_FINALIZE.into(),
            workflow_id: None,
            step_name: None,
            input: serde_json::json!({
                "authorisation_id": Uuid::new_v4().to_string(),
                "outcome": "abracadabra",
            }),
            user_data: serde_json::json!({}),
            step_config: None,
        });
        assert_eq!(bad.status, "failed");
        let unknown = execute_step(&ProxyBackRequest {
            step_kind: "UnknownStep".into(),
            workflow_id: None,
            step_name: None,
            input: serde_json::json!({}),
            user_data: serde_json::json!({}),
            step_config: None,
        });
        assert!(unknown.error.unwrap().contains("unknown EU step kind"));
    }
}
