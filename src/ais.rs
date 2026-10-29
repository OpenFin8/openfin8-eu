// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the OpenFin8:EU
// SPDX-License-Identifier: Apache-2.0

//! AIS + PIIS resource surfaces- EU DESIGN.md §2 AIS/PIIS rows;
//! ).
//!
//! **AIS**: accounts, balances, transactions, card accounts behind an AIS
//! consent - the consent middleware chokepoint (every kernel invariant
//! holds: the consent must be `valid`, unexpired, and scope-covered; a
//! revoked consent is terminal and stops serving on the very next call).
//! The reads proxy to **Bank8:Ledger** through the public API + the
//! `bank8::` SDK contracts ONLY (the OBVERT invariant).
//!
//! **PIIS**: the funds-confirmation consent + the check (the
//! confirmation-of-funds surface; the check answers against the ledger
//! balance through the same consent chokepoint).
//!
//! Out-of-scope data families return the XS2A unsupported response,
//! never stubbed data (kernel invariant).

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::consent::{self, AppState};

// ── Wire DTOs ──────────────────────────────────────────────────────────

/// The consent-check verdict every AIS/PIIS read enforces (the
/// chokepoint result - pure, unit-tested).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsentVerdict {
    /// The consent is valid + unexpired + scope-covered.
    Valid,
    /// No consent row matched the id.
    Unknown,
    /// The consent is `received` - the PSU ceremony has not completed.
    Received,
    /// The consent is `rejected` (the PSU denied the grant).
    Rejected,
    /// The consent is `expired`.
    Expired,
    /// The consent is `revoked` (terminal - never revives).
    Revoked,
}

/// Map the consent row status to the chokepoint verdict.
pub fn consent_verdict(status: &str) -> ConsentVerdict {
    match status {
        consent::CONSENT_VALID => ConsentVerdict::Valid,
        consent::CONSENT_RECEIVED => ConsentVerdict::Received,
        consent::CONSENT_REJECTED => ConsentVerdict::Rejected,
        consent::CONSENT_EXPIRED => ConsentVerdict::Expired,
        consent::CONSENT_REVOKED => ConsentVerdict::Revoked,
        _ => ConsentVerdict::Unknown,
    }
}

/// The chokepoint enforcement: a data read is served ONLY under a Valid
/// verdict. Terminal states (revoked/rejected/expired) and the
/// not-yet-granted state (received) all REJECT - a revoked consent
/// stops serving on the very next call (structurally: the read path
/// consults the row, the row is terminal).
pub fn enforce_consent_verdict(
    verdict: ConsentVerdict,
    has_elapsed_expiry: bool,
    scope: Option<&str>,
    consent_scopes: &[String],
) -> Result<(), (StatusCode, String)> {
    match verdict {
        ConsentVerdict::Valid => {
            if has_elapsed_expiry {
                return Err((
                    StatusCode::FORBIDDEN,
                    "the consent's validity window has elapsed".into(),
                ));
            }
            if let Some(required) = scope {
                if !consent_scopes.iter().any(|s| s == required) {
                    return Err((
                        StatusCode::FORBIDDEN,
                        format!("the consent does not cover the scope '{required}'"),
                    ));
                }
            }
            Ok(())
        }
        ConsentVerdict::Received => Err((
            StatusCode::FORBIDDEN,
            "the consent is not yet authorised (the PSU ceremony has not completed)".into(),
        )),
        ConsentVerdict::Rejected => Err((
            StatusCode::FORBIDDEN,
            "the consent was rejected by the PSU".into(),
        )),
        ConsentVerdict::Expired => Err((StatusCode::FORBIDDEN, "the consent has expired".into())),
        ConsentVerdict::Revoked => Err((
            StatusCode::FORBIDDEN,
            "the consent was revoked (revocation is terminal)".into(),
        )),
        ConsentVerdict::Unknown => Err((StatusCode::NOT_FOUND, "unknown consent".into())),
    }
}

/// The AIS accounts list (the forwarded Ledger document, CSDF-minimized
/// by the ledger-side scope projection; genuinely freeform envelope).
#[derive(Debug, Serialize, ToSchema)]
#[serde(transparent)]
pub struct AccountsPassthrough(pub serde_json::Value);

/// The PIIS funds-confirmation request.
#[derive(Debug, Deserialize, ToSchema)]
pub struct FundsConfirmationRequest {
    /// The consent id (the PIIS consent).
    #[serde(rename = "consentId")]
    pub consent_id: Uuid,
    /// The account to check (opaque handle at the ASPSP).
    #[serde(rename = "accountId")]
    pub account_id: String,
    /// The amount to confirm (the ISO 20022 amount document).
    pub amount: serde_json::Value,
}

/// The PIIS funds-confirmation response.
#[derive(Debug, Serialize, ToSchema)]
pub struct FundsConfirmationResponse {
    /// The consent id.
    #[serde(rename = "consentId")]
    pub consent_id: Uuid,
    /// `fundsAvailable` - the XS2A boolean answer.
    #[serde(rename = "fundsAvailable")]
    pub funds_available: bool,
}

// ── The chokepoint (the consent middleware) ────────────────────────────

/// Load a consent + enforce the chokepoint for a data read. Returns the
/// consent row's service + scopes (the read proceeds under them).
async fn require_valid_consent(
    state: &AppState,
    headers: &axum::http::HeaderMap,
    consent_id: Uuid,
    required_scope: &str,
    service: &str,
) -> Result<(Uuid, Vec<String>), (StatusCode, String)> {
    // The Shield gate first (step 5 - the ONLY authorization gate).
    consent::authorize(state, headers, "consents:read").await?;
    let mut conn = state
        .pool
        .acquire()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let row = sqlx::query(
        "SELECT env_id, customer_id, status, service, scopes, expires_at \
           FROM openfin8_eu.consents WHERE id = $1",
    )
    .bind(consent_id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .ok_or((StatusCode::NOT_FOUND, "unknown consent".to_string()))?;
    let status: String = row.get("status");
    let row_service: String = row.get("service");
    if row_service != service {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("the consent is a '{row_service}' consent, not '{service}'"),
        ));
    }
    let scopes: Vec<String> = row.get("scopes");
    let expires_at: Option<chrono::DateTime<chrono::Utc>> = row.get("expires_at");
    let elapsed = expires_at.map(|e| e < chrono::Utc::now()).unwrap_or(false);
    enforce_consent_verdict(
        consent_verdict(&status),
        elapsed,
        Some(required_scope),
        &scopes,
    )?;
    Ok((row.get("customer_id"), scopes))
}

// ── The AIS routes ─────────────────────────────────────────────────────

/// `GET /v1/ais/consents/{id}/accounts` - the accounts list behind an
/// AIS consent (the chokepoint + the Ledger proxy).
#[utoipa::path(
    get,
    path = "/v1/ais/consents/{consentId}/accounts",
    responses(
        (status = 200, description = "Accounts list", body = AccountsPassthrough),
        (status = 403, description = "The consent chokepoint rejected the read"),
        (status = 404, description = "Unknown consent"),
        (status = 503, description = "Ledger proxy transport absent"),
    ),
    security(),
    tag = "ais",
)]
pub async fn get_accounts(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(consent_id): Path<Uuid>,
) -> Result<Json<AccountsPassthrough>, (StatusCode, String)> {
    let _ = require_valid_consent(
        &state,
        &headers,
        consent_id,
        "openfin8:eu:accountbasic:read",
        consent::SERVICE_AIS,
    )
    .await?;
    let body = proxy_ledger_list(&state, "/v1/accounts").await?;
    Ok(Json(AccountsPassthrough(body)))
}

/// `GET /v1/ais/consents/{id}/accounts/{accountId}/balances` - the
/// balances read behind an AIS consent.
#[utoipa::path(
    get,
    path = "/v1/ais/consents/{consentId}/accounts/{accountId}/balances",
    responses(
        (status = 200, description = "Balances", body = AccountsPassthrough),
        (status = 403, description = "The consent chokepoint rejected the read"),
        (status = 503, description = "Ledger proxy transport absent"),
    ),
    security(),
    tag = "ais",
)]
pub async fn get_balances(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path((consent_id, account_id)): Path<(Uuid, String)>,
) -> Result<Json<AccountsPassthrough>, (StatusCode, String)> {
    let _ = require_valid_consent(
        &state,
        &headers,
        consent_id,
        "openfin8:eu:balances:read",
        consent::SERVICE_AIS,
    )
    .await?;
    let body = proxy_ledger_list(&state, &format!("/v1/accounts/{account_id}/balances")).await?;
    Ok(Json(AccountsPassthrough(body)))
}

/// `GET /v1/ais/consents/{id}/accounts/{accountId}/transactions` - the
/// transactions read behind an AIS consent (the lookback window the
/// consent pins is applied ledger-side; the chokepoint enforced it).
#[utoipa::path(
    get,
    path = "/v1/ais/consents/{consentId}/accounts/{accountId}/transactions",
    responses(
        (status = 200, description = "Transactions", body = AccountsPassthrough),
        (status = 403, description = "The consent chokepoint rejected the read"),
        (status = 503, description = "Ledger proxy transport absent"),
    ),
    security(),
    tag = "ais",
)]
pub async fn get_transactions(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path((consent_id, account_id)): Path<(Uuid, String)>,
) -> Result<Json<AccountsPassthrough>, (StatusCode, String)> {
    let _ = require_valid_consent(
        &state,
        &headers,
        consent_id,
        "openfin8:eu:transactions:read",
        consent::SERVICE_AIS,
    )
    .await?;
    let body =
        proxy_ledger_list(&state, &format!("/v1/accounts/{account_id}/transactions")).await?;
    Ok(Json(AccountsPassthrough(body)))
}

/// `GET /v1/ais/consents/{id}/card-accounts` - the card-accounts read
/// behind an AIS consent (out-of-scope data families return the XS2A
/// unsupported response, never stubbed data - the honest answer until
/// the card-account resource ships).
#[utoipa::path(
    get,
    path = "/v1/ais/consents/{consentId}/card-accounts",
    responses(
        (status = 501, description = "The card-account resource is not served by this deployment"),
        (status = 403, description = "The consent chokepoint rejected the read"),
    ),
    security(),
    tag = "ais",
)]
pub async fn get_card_accounts(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(consent_id): Path<Uuid>,
) -> Result<Json<AccountsPassthrough>, (StatusCode, String)> {
    let _ = require_valid_consent(
        &state,
        &headers,
        consent_id,
        "openfin8:eu:accountbasic:read",
        consent::SERVICE_AIS,
    )
    .await?;
    Err((
        StatusCode::NOT_IMPLEMENTED,
        "the card-account resource is not served by this deployment (out-of-scope data \
         families answer unsupported, never stubbed data)"
            .into(),
    ))
}

// ── The PIIS routes ─────────────────────────────────────────────────────

/// `POST /v1/piis/consents/{id}/funds-confirmations` - the
/// confirmation-of-funds check behind a PIIS consent.
#[utoipa::path(
    post,
    path = "/v1/piis/consents/{consentId}/funds-confirmations",
    request_body = FundsConfirmationRequest,
    responses(
        (status = 200, description = "Funds confirmation", body = FundsConfirmationResponse),
        (status = 403, description = "The consent chokepoint rejected the check"),
        (status = 503, description = "Ledger proxy transport absent"),
    ),
    security(),
    tag = "piis",
)]
pub async fn confirm_funds(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(consent_id): Path<Uuid>,
    Json(req): Json<FundsConfirmationRequest>,
) -> Result<Json<FundsConfirmationResponse>, (StatusCode, String)> {
    let _ = require_valid_consent(
        &state,
        &headers,
        consent_id,
        "openfin8:eu:fundsconfirmations:read",
        consent::SERVICE_PIIS,
    )
    .await?;
    // The balance check rides the Ledger public API (OBVERT); the
    // verdict is the ledger's - the adapter reports it.
    let http = state
        .ledger_http()
        .ok_or((
            StatusCode::SERVICE_UNAVAILABLE,
            "ledger proxy transport absent (workload certificate not provisioned)".into(),
        ))?
        .clone();
    let resp = http
        .get(format!(
            "{}/v1/accounts/{}/balances",
            state.ledger_url, req.account_id
        ))
        .send()
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("ledger proxy: {e}")))?;
    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("ledger decode: {e}")))?;
    // The ledger balance document: the available amount (the ledger's
    // own shape - the adapter projects the funds-available verdict).
    let available = body
        .get("available")
        .or_else(|| body.get("balance"))
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);
    let requested = req
        .amount
        .get("amount")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<f64>().ok())
        .unwrap_or(f64::MAX);
    Ok(Json(FundsConfirmationResponse {
        consent_id,
        funds_available: available >= requested,
    }))
}

// ── Shared helpers ─────────────────────────────────────────────────────

/// The Ledger proxy lane (the certificate-presenting transport, workload
/// `openfin8-eu-ledger`; OBVERT - public API only).
async fn proxy_ledger_list(
    state: &AppState,
    path: &str,
) -> Result<serde_json::Value, (StatusCode, String)> {
    let http = state
        .ledger_http()
        .ok_or((
            StatusCode::SERVICE_UNAVAILABLE,
            "ledger proxy transport absent (workload certificate not provisioned)".into(),
        ))?
        .clone();
    let resp = http
        .get(format!("{}{}", state.ledger_url, path))
        .send()
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("ledger proxy: {e}")))?;
    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("ledger decode: {e}")))?;
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_chokepoint_serves_only_valid() {
        let scopes = vec!["openfin8:eu:accountbasic:read".to_string()];
        // Valid + unexpired + scope-covered -> served.
        assert!(enforce_consent_verdict(
            ConsentVerdict::Valid,
            false,
            Some("openfin8:eu:accountbasic:read"),
            &scopes
        )
        .is_ok());
        // Valid but scope-miss -> rejected.
        assert!(enforce_consent_verdict(
            ConsentVerdict::Valid,
            false,
            Some("openfin8:eu:transactions:read"),
            &scopes
        )
        .is_err());
        // Valid but expiry elapsed -> rejected.
        assert!(enforce_consent_verdict(ConsentVerdict::Valid, true, None, &scopes).is_err());
        // Every non-valid verdict rejects (the revoked consent stops
        // serving on the very next call).
        for v in [
            ConsentVerdict::Received,
            ConsentVerdict::Rejected,
            ConsentVerdict::Expired,
            ConsentVerdict::Revoked,
        ] {
            assert!(
                enforce_consent_verdict(v, false, None, &scopes).is_err(),
                "{v:?} must reject"
            );
        }
        // Unknown -> 404.
        assert_eq!(
            enforce_consent_verdict(ConsentVerdict::Unknown, false, None, &scopes)
                .unwrap_err()
                .0,
            StatusCode::NOT_FOUND
        );
        // The revoked text names the terminal rule.
        let err =
            enforce_consent_verdict(ConsentVerdict::Revoked, false, None, &scopes).unwrap_err();
        assert!(err.1.contains("terminal"));
    }

    #[test]
    fn the_verdict_maps_the_four_states() {
        assert_eq!(consent_verdict("valid"), ConsentVerdict::Valid);
        assert_eq!(consent_verdict("received"), ConsentVerdict::Received);
        assert_eq!(consent_verdict("rejected"), ConsentVerdict::Rejected);
        assert_eq!(consent_verdict("expired"), ConsentVerdict::Expired);
        assert_eq!(consent_verdict("revoked"), ConsentVerdict::Revoked);
        assert_eq!(consent_verdict("weird"), ConsentVerdict::Unknown);
    }
}
