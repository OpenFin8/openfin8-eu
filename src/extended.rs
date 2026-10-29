// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the OpenFin8:EU
// SPDX-License-Identifier: Apache-2.0

//! The Extended Services suite- EU DESIGN.md §2 Extended row;
//! ).
//!
//! Scoped per BUSINESS §2 row 6: **mandates**, **RTP (request-to-pay)**,
//! **push AIS**, **discovery**, **documents**. Each surface answers
//! honestly: the discovery document is served (the deployment's
//! advertisement); the data surfaces return the XS2A unsupported
//! response until their resource families ship (never stubbed data -
//! the kernel invariant: out-of-scope data families return the
//! standard's unsupported response).

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde::Serialize;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::consent::AppState;

// ── Wire DTOs ──────────────────────────────────────────────────────────

/// The discovery document: the deployment's served-surface advertisement
/// (the XS2A discovery response - the honest per-environment list).
#[derive(Debug, Serialize, ToSchema)]
pub struct DiscoveryResponse {
    /// The Berlin Group openFinance version this ASPSP serves.
    #[serde(rename = "ofVersion")]
    pub of_version: String,
    /// The served SCA approaches (redirect always present).
    #[serde(rename = "scaApproaches")]
    pub sca_approaches: Vec<String>,
    /// The served ISO payment products.
    #[serde(rename = "paymentProducts")]
    pub payment_products: Vec<String>,
    /// The Extended Services this deployment serves.
    pub extensions: Vec<String>,
}

/// An out-of-scope data-family document (the honest unsupported answer).
#[derive(Debug, Serialize, ToSchema)]
pub struct UnsupportedResponse {
    /// The unserved resource family.
    pub resource: String,
    /// The honest statement (never stubbed data).
    pub reason: String,
}

// ── The routes ──────────────────────────────────────────────────────────

/// `GET /v1/discovery` - the served-surface advertisement (the honest
/// per-environment list: the SCA approaches, the payment products, the
/// extended services).
#[utoipa::path(
    get,
    path = "/v1/discovery",
    responses(
        (status = 200, description = "Discovery document", body = DiscoveryResponse),
    ),
    security(),
    tag = "extended",
)]
pub async fn discovery(State(state): State<AppState>) -> Json<DiscoveryResponse> {
    Json(DiscoveryResponse {
        of_version: state.of_version.clone(),
        sca_approaches: state.served_approaches.clone(),
        payment_products: crate::payments::PAYMENT_PRODUCTS
            .iter()
            .map(|s| s.to_string())
            .collect(),
        extensions: vec![],
    })
}

/// `GET /v1/mandates` - the mandate (recurring-payment authorization)
/// list. Out-of-scope until the mandate resource family ships: the
/// honest unsupported response, never stubbed data.
#[utoipa::path(
    get,
    path = "/v1/mandates",
    responses(
        (status = 501, description = "The mandate resource family is not served", body = UnsupportedResponse),
    ),
    security(),
    tag = "extended",
)]
pub async fn list_mandates() -> (StatusCode, Json<UnsupportedResponse>) {
    unsupported("mandates")
}

/// `GET /v1/request-to-pay` - the RTP (request-to-pay) list. Out-of-scope
/// until the RTP resource family ships.
#[utoipa::path(
    get,
    path = "/v1/request-to-pay",
    responses(
        (status = 501, description = "The RTP resource family is not served", body = UnsupportedResponse),
    ),
    security(),
    tag = "extended",
)]
pub async fn list_request_to_pay() -> (StatusCode, Json<UnsupportedResponse>) {
    unsupported("request-to-pay")
}

/// `GET /v1/push-ais` - the push-AIS (consent-less account
/// presentation) list. Out-of-scope until the push-AIS resource family
/// ships.
#[utoipa::path(
    get,
    path = "/v1/push-ais",
    responses(
        (status = 501, description = "The push-AIS resource family is not served", body = UnsupportedResponse),
    ),
    security(),
    tag = "extended",
)]
pub async fn list_push_ais() -> (StatusCode, Json<UnsupportedResponse>) {
    unsupported("push-ais")
}

/// `GET /v1/documents/{documentId}` - document download. The Extended
/// Services documents surface: rides Sentin8:Storage signed URLs (the
/// CA statement-download precedent) once the document resource family
/// ships; the honest unsupported answer until then.
#[utoipa::path(
    get,
    path = "/v1/documents/{documentId}",
    responses(
        (status = 501, description = "The document resource family is not served", body = UnsupportedResponse),
    ),
    security(),
    tag = "extended",
)]
pub async fn download_document(
    Path(document_id): Path<Uuid>,
) -> (StatusCode, Json<UnsupportedResponse>) {
    let _ = document_id;
    unsupported("documents")
}

/// The honest unsupported response (the kernel invariant: out-of-scope
/// data families return the standard's unsupported response, never
/// stubbed data).
fn unsupported(resource: &str) -> (StatusCode, Json<UnsupportedResponse>) {
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(UnsupportedResponse {
            resource: resource.to_string(),
            reason: "this resource family is not served by this deployment \
                     (out-of-scope data families answer unsupported, never stubbed data)"
                .into(),
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsupported_answers_name_the_resource() {
        let (status, body) = unsupported("mandates");
        assert_eq!(status, StatusCode::NOT_IMPLEMENTED);
        assert_eq!(body.resource, "mandates");
        assert!(body.reason.contains("never stubbed data"));
    }
}
