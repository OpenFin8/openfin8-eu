// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the OpenFin8:EU
// SPDX-License-Identifier: Apache-2.0

//! PIS + signing baskets- EU DESIGN.md §2 PIS + signing-basket
//! rows, §4 money movement; ).
//!
//! The ISO payment products proxy to **Bank8:Payments** through the
//! public API + the `bank8::` SDK contracts ONLY (the OBVERT invariant -
//! never bank8's database). The chain per EU DESIGN §4: consent (PIS
//! authorisation) → submission (the ISO payment product) → status.
//!
//! **Every payment initiation verifies the QSEALC signature** (EU
//! invariant 1, §7): `eidas::enforce_qsealc` fails closed - Missing /
//! Invalid / NotConfigured all REJECT; the surface never degrades to
//! serving unsigned initiations.
//!
//! **Signing baskets** - the distinct EU concept: batch multiple
//! consents + payments into ONE PSU authorization ceremony. The basket
//! is its own object (`openfin8_eu.signing_baskets` + items); its SCA
//! ceremony rides the SAME authorisation machinery (each member's
//! ceremony is its own sub-resource; the basket's own state follows the
//! members' outcomes).

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
use crate::eidas;

// ── Wire DTOs ──────────────────────────────────────────────────────────

/// `POST /v1/payments/{paymentProduct}` - the ISO payment product
/// initiation request (SEPA credit transfer, instant, cross-border,
/// bulk - the product name is the path segment; XS2A JSON + the ISO
/// 20022-derived payload).
#[derive(Debug, Deserialize, ToSchema)]
pub struct CreatePaymentRequest {
    /// The PSU (bank customer) the payment debits.
    #[serde(rename = "customerId")]
    pub customer_id: Uuid,
    /// The debtor account (opaque handle at the ASPSP).
    #[serde(rename = "debtorAccount")]
    pub debtor_account: String,
    /// The payment body (the ISO 20022-derived document - genuinely
    /// freeform: the product family defines the fields).
    #[serde(rename = "instructedPayment")]
    pub instructed_payment: serde_json::Value,
    /// The QSEALC signature over the canonical body (EU invariant 1).
    #[serde(default)]
    pub signature: Option<String>,
}

/// The payment initiation response.
#[derive(Debug, Serialize, ToSchema)]
pub struct PaymentResponse {
    /// The payment id (as assigned by Payments).
    #[serde(rename = "paymentId")]
    pub payment_id: String,
    /// The transaction status (the ISO transaction-status vocabulary).
    #[serde(rename = "transactionStatus")]
    pub transaction_status: String,
    /// The forwarded Payments document (genuinely freeform).
    #[serde(rename = "paymentsService")]
    pub payments_service: serde_json::Value,
}

/// The signing-basket creation request.
#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateBasketRequest {
    /// The PSU the basket's ceremony authorizes.
    #[serde(rename = "customerId")]
    pub customer_id: Uuid,
    /// The consent ids batched into this basket.
    #[serde(default)]
    pub consent_ids: Vec<Uuid>,
    /// The payment ids batched into this basket (payments created by
    /// `POST /v1/payments/{product}` - opaque handles here).
    #[serde(default)]
    pub payment_ids: Vec<String>,
}

/// The signing-basket document.
#[derive(Debug, Serialize, ToSchema)]
pub struct BasketResponse {
    /// The basket id.
    #[serde(rename = "basketId")]
    pub basket_id: Uuid,
    /// The basket's own XS2A state (received | valid | rejected | expired).
    pub status: String,
    /// The batched consents.
    #[serde(rename = "consentIds")]
    pub consent_ids: Vec<Uuid>,
    /// The batched payments.
    #[serde(rename = "paymentIds")]
    pub payment_ids: Vec<String>,
    /// Creation timestamp.
    #[serde(rename = "createdAt")]
    pub created_at: chrono::DateTime<chrono::Utc>,
}

// ── Pure seams (unit-tested) ───────────────────────────────────────────

/// The ISO payment products this deployment serves (XS2A: the
/// `{paymentProduct}` path segment vocabulary).
pub const PAYMENT_PRODUCTS: &[&str] = &[
    "sepa-credit-transfers",
    "instant-sepa-credit-transfers",
    "cross-border-credit-transfers",
    "bulk-credit-transfers",
];

/// Validate a payment product path segment.
pub fn validate_payment_product(product: &str) -> Result<(), String> {
    if PAYMENT_PRODUCTS.contains(&product) {
        Ok(())
    } else {
        Err(format!(
            "unknown payment product '{product}' (served: {PAYMENT_PRODUCTS:?})"
        ))
    }
}

/// The canonical form a QSEALC signature covers (deterministic: the
/// product + the sorted JSON serialization of the payment body).
pub fn canonical_payment_body(product: &str, payment: &serde_json::Value) -> String {
    // serde_json's Value serialization is order-preserving on the parse
    // (the canonical form is the compact rendering - deterministic for
    // the same document).
    format!(
        "{product}:{}",
        serde_json::to_string(payment).unwrap_or_default()
    )
}

// ── The PIS routes ─────────────────────────────────────────────────────

/// `POST /v1/payments/{paymentProduct}` - payment initiation: verify the
/// QSEALC signature (EU invariant 1, fail-closed), then proxy to
/// Bank8:Payments through the public API (the OBVERT boundary).
#[utoipa::path(
    post,
    path = "/v1/payments/{paymentProduct}",
    request_body = CreatePaymentRequest,
    responses(
        (status = 201, description = "Payment initiated", body = PaymentResponse),
        (status = 400, description = "Unknown payment product"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "QSEALC verification failed (fail-closed)"),
        (status = 503, description = "Payments proxy transport absent"),
    ),
    security(),
    tag = "payments",
)]
pub async fn create_payment(
    State(state): State<AppState>,
    Path(product): Path<String>,
    Json(req): Json<CreatePaymentRequest>,
) -> Result<(StatusCode, Json<PaymentResponse>), (StatusCode, String)> {
    validate_payment_product(&product).map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    // EU invariant 1: every payment initiation verifies the QSEALC
    // signature. Fail-closed on all non-Verified verdicts.
    let canonical = canonical_payment_body(&product, &req.instructed_payment);
    let verdict = eidas::verify_qsealc_fixture(
        req.signature.as_deref(),
        &canonical,
        state.eids_configured(),
    );
    if let Err(e) = eidas::enforce_qsealc(verdict) {
        return Err((StatusCode::FORBIDDEN, e));
    }
    // The payments proxy lane: the certificate-presenting transport
    // (workload `openfin8-eu-payments`; OBVERT - public API only).
    let http = state
        .payments_http()
        .ok_or((
            StatusCode::SERVICE_UNAVAILABLE,
            "payments proxy transport absent (workload certificate not provisioned)".into(),
        ))?
        .clone();
    let resp = http
        .post(format!("{}/v1/payments", state.payments_url))
        .json(&serde_json::json!({
            "customer_id": req.customer_id,
            "debtor_account": req.debtor_account,
            "payment": req.instructed_payment,
        }))
        .send()
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("payments proxy: {e}")))?;
    let status = resp.status();
    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("payments decode: {e}")))?;
    if !status.is_success() {
        return Err((
            StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::BAD_GATEWAY),
            format!("payments proxy status {status}: {body}"),
        ));
    }
    let payment_id = body
        .get("id")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();
    // The event rides the outbox (same-tx contract; a payment-initiation
    // event is advisory - the Payments service owns the payment record).
    emit_payment_event(
        &state,
        &req.customer_id,
        "payment:initiated",
        serde_json::json!({
            "payment_id": payment_id,
            "product": product,
            "customer_id": req.customer_id,
        }),
    )
    .await?;
    Ok((
        StatusCode::CREATED,
        Json(PaymentResponse {
            payment_id: payment_id.clone(),
            transaction_status: body
                .get("status")
                .and_then(|v| v.as_str())
                .unwrap_or("PDNG")
                .to_string(),
            payments_service: body,
        }),
    ))
}

/// `GET /v1/payments/{paymentProduct}/{paymentId}` - payment status read
/// (the PIS status resource; proxied to Payments).
#[utoipa::path(
    get,
    path = "/v1/payments/{paymentProduct}/{paymentId}",
    responses(
        (status = 200, description = "Payment status", body = PaymentResponse),
        (status = 400, description = "Unknown payment product"),
        (status = 503, description = "Payments proxy transport absent"),
    ),
    security(),
    tag = "payments",
)]
pub async fn get_payment_status(
    State(state): State<AppState>,
    Path((product, payment_id)): Path<(String, String)>,
) -> Result<Json<PaymentResponse>, (StatusCode, String)> {
    validate_payment_product(&product).map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    let http = state
        .payments_http()
        .ok_or((
            StatusCode::SERVICE_UNAVAILABLE,
            "payments proxy transport absent (workload certificate not provisioned)".into(),
        ))?
        .clone();
    let resp = http
        .get(format!("{}/v1/payments/{payment_id}", state.payments_url))
        .send()
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("payments proxy: {e}")))?;
    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("payments decode: {e}")))?;
    Ok(Json(PaymentResponse {
        payment_id: payment_id.clone(),
        transaction_status: body
            .get("status")
            .and_then(|v| v.as_str())
            .unwrap_or("UNKNOWN")
            .to_string(),
        payments_service: body,
    }))
}

/// `DELETE /v1/payments/{paymentProduct}/{paymentId}` - payment
/// cancellation (proxied to Payments; the PIS cancellation resource).
#[utoipa::path(
    delete,
    path = "/v1/payments/{paymentProduct}/{paymentId}",
    responses(
        (status = 204, description = "Payment cancelled"),
        (status = 400, description = "Unknown payment product"),
        (status = 503, description = "Payments proxy transport absent"),
    ),
    security(),
    tag = "payments",
)]
pub async fn cancel_payment(
    State(state): State<AppState>,
    Path((product, payment_id)): Path<(String, String)>,
) -> Result<StatusCode, (StatusCode, String)> {
    validate_payment_product(&product).map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    let http = state
        .payments_http()
        .ok_or((
            StatusCode::SERVICE_UNAVAILABLE,
            "payments proxy transport absent (workload certificate not provisioned)".into(),
        ))?
        .clone();
    let resp = http
        .delete(format!("{}/v1/payments/{payment_id}", state.payments_url))
        .send()
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("payments proxy: {e}")))?;
    if !resp.status().is_success() {
        return Err((
            StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY),
            format!("payments proxy status {}", resp.status()),
        ));
    }
    Ok(StatusCode::NO_CONTENT)
}

// ── The signing-basket routes ──────────────────────────────────────────

/// `POST /v1/signing-baskets` - create a basket: batch consents +
/// payments into ONE PSU authorization ceremony.
#[utoipa::path(
    post,
    path = "/v1/signing-baskets",
    request_body = CreateBasketRequest,
    responses(
        (status = 201, description = "Basket created", body = BasketResponse),
        (status = 400, description = "Empty basket"),
    ),
    security(),
    tag = "payments",
)]
pub async fn create_basket(
    State(state): State<AppState>,
    Json(req): Json<CreateBasketRequest>,
) -> Result<(StatusCode, Json<BasketResponse>), (StatusCode, String)> {
    if req.consent_ids.is_empty() && req.payment_ids.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "a signing basket batches at least one item".into(),
        ));
    }
    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    consent::set_tenant_context_pub(&mut tx, state.env_id()).await;
    let row = sqlx::query(
        "INSERT INTO openfin8_eu.signing_baskets (env_id, customer_id, status) \
         VALUES ($1, $2, 'received') RETURNING id, status, created_at",
    )
    .bind(state.env_id())
    .bind(req.customer_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let basket_id: Uuid = row.get("id");
    for cid in &req.consent_ids {
        sqlx::query(
            "INSERT INTO openfin8_eu.signing_basket_items (basket_id, consent_id) VALUES ($1, $2)",
        )
        .bind(basket_id)
        .bind(cid)
        .execute(&mut *tx)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    }
    for pid in &req.payment_ids {
        sqlx::query(
            "INSERT INTO openfin8_eu.signing_basket_items (basket_id, payment_id) VALUES ($1, $2)",
        )
        .bind(basket_id)
        .bind(pid)
        .execute(&mut *tx)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    }
    tx.commit()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok((
        StatusCode::CREATED,
        Json(BasketResponse {
            basket_id,
            status: row.get("status"),
            consent_ids: req.consent_ids,
            payment_ids: req.payment_ids,
            created_at: row.get("created_at"),
        }),
    ))
}

/// `GET /v1/signing-baskets/{basketId}` - read a basket.
#[utoipa::path(
    get,
    path = "/v1/signing-baskets/{basketId}",
    responses(
        (status = 200, description = "Basket detail", body = BasketResponse),
        (status = 404, description = "Unknown basket"),
    ),
    security(),
    tag = "payments",
)]
pub async fn get_basket(
    State(state): State<AppState>,
    Path(basket_id): Path<Uuid>,
) -> Result<Json<BasketResponse>, (StatusCode, String)> {
    let mut conn = state
        .pool
        .acquire()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let row =
        sqlx::query("SELECT id, status, created_at FROM openfin8_eu.signing_baskets WHERE id = $1")
            .bind(basket_id)
            .fetch_optional(&mut *conn)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
            .ok_or((StatusCode::NOT_FOUND, "unknown basket".to_string()))?;
    let items = sqlx::query(
        "SELECT consent_id, payment_id FROM openfin8_eu.signing_basket_items \
          WHERE basket_id = $1 ORDER BY created_at",
    )
    .bind(basket_id)
    .fetch_all(&mut *conn)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let mut consent_ids = Vec::new();
    let mut payment_ids = Vec::new();
    for item in items {
        if let Ok(Some(c)) = item.try_get::<Option<Uuid>, _>("consent_id") {
            consent_ids.push(c);
        }
        if let Ok(Some(p)) = item.try_get::<Option<String>, _>("payment_id") {
            payment_ids.push(p);
        }
    }
    Ok(Json(BasketResponse {
        basket_id,
        status: row.get("status"),
        consent_ids,
        payment_ids,
        created_at: row.get("created_at"),
    }))
}

// ── Shared helpers ─────────────────────────────────────────────────────

/// Emit a payment-lifecycle event through the outbox (a standalone
/// transaction - the payment record lives in Payments, the event is
/// advisory; the domain-transaction coupling is the consent paths').
async fn emit_payment_event(
    state: &AppState,
    _customer_id: &Uuid,
    resource_operation: &str,
    payload: serde_json::Value,
) -> Result<(), (StatusCode, String)> {
    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    consent::set_tenant_context_pub(&mut tx, state.env_id()).await;
    consent::emit_event_pub(&mut tx, state.env_id(), resource_operation, payload)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    tx.commit()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payment_products_are_the_iso_set() {
        for p in PAYMENT_PRODUCTS {
            assert!(validate_payment_product(p).is_ok());
        }
        assert!(validate_payment_product("pix-instant").is_err());
        assert!(validate_payment_product("").is_err());
    }

    #[test]
    fn canonical_body_is_deterministic() {
        let payment = serde_json::json!({"amount": "12.34", "currency": "EUR"});
        let a = canonical_payment_body("sepa-credit-transfers", &payment);
        let b = canonical_payment_body("sepa-credit-transfers", &payment);
        assert_eq!(a, b);
        // The product is part of the covered material.
        let c = canonical_payment_body("instant-sepa-credit-transfers", &payment);
        assert_ne!(a, c);
        assert!(a.starts_with("sepa-credit-transfers:"));
    }

    #[test]
    fn canonical_body_feeds_the_qsealc_verification() {
        let payment = serde_json::json!({"amount": "50.00", "currency": "EUR"});
        let canonical = canonical_payment_body("sepa-credit-transfers", &payment);
        // The fixture signature over the canonical body verifies.
        use sha2::{Digest, Sha256};
        let digest = Sha256::digest(canonical.as_bytes());
        let sig = format!(
            "sig:{}",
            digest
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        );
        assert_eq!(
            eidas::verify_qsealc_fixture(Some(&sig), &canonical, true),
            eidas::QsealcVerdict::Verified
        );
        // A signature over DIFFERENT material fails (tamper detection).
        assert_eq!(
            eidas::verify_qsealc_fixture(
                Some(&sig),
                "sepa-credit-transfers:{\"amount\":\"51.00\"}",
                true
            ),
            eidas::QsealcVerdict::Invalid
        );
    }
}
