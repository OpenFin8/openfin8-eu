// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the OpenFin8:EU
// SPDX-License-Identifier: Apache-2.0

//! The eIDAS trust path + bank-by-bank DCR (OBARCH-7 - EU DESIGN.md §3
//! ceremonies 1-2, §5, §7 invariant 1; backlog EU-4).
//!
//! **No central directory**: recipient onboarding is DCR per ASPSP
//! (RFC 7591) against each bank's own AS - the EU trust model (contrast
//! the UK's OB Directory). The ceremony ctx carries the per-environment
//! eIDAS certificate references:
//!
//! - **QWAC** (Qualified Website Authentication Certificate) - TLS
//!   client auth: `OPENFIN8_EU_QWAC_CERT_REF`/`_KEY_REF`.
//! - **QSEALC** (Qualified Electronic Seal) - request signing:
//!   `OPENFIN8_EU_QSEALC_CERT_REF`/`_KEY_REF`.
//!
//! Both are **secret references only** (`sentin8-secrets://…` -
//! `secrets::SecretsClient` resolves them at runtime): never key
//! material in a column or an env var (the AUDIT_FINDINGS contract).
//! Every payment initiation verifies the QSEALC signature (§7, EU
//! invariant 1 - the PIS surface enforces it, `payments.rs`).

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

/// The eIDAS certificate-kind pair a ceremony carries (secret
/// references, never key material).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct EidasCertRefs {
    /// The QWAC certificate reference (`sentin8-secrets://…`) - TLS
    /// client auth.
    #[serde(rename = "qwacCertRef")]
    pub qwac_cert_ref: String,
    /// The QWAC private-key reference.
    #[serde(rename = "qwacKeyRef")]
    pub qwac_key_ref: String,
    /// The QSEALC certificate reference - request signing.
    #[serde(rename = "qsealcCertRef")]
    pub qsealc_cert_ref: String,
    /// The QSEALC private-key reference.
    #[serde(rename = "qsealcKeyRef")]
    pub qsealc_key_ref: String,
}

/// Validate a secret reference shape (`sentin8-secrets://<name>`).
/// The value itself is NEVER loaded here - resolution happens at the
/// call site against the Secrets service (the reference travels in
/// config + ceremony ctx; the material never does).
pub fn validate_secret_ref(reference: &str) -> Result<(), String> {
    let name = reference
        .strip_prefix("sentin8-secrets://")
        .ok_or_else(|| format!("not a sentin8-secrets:// reference: '{reference}'"))?;
    if name.trim().is_empty() {
        return Err("the secret reference names no secret".into());
    }
    Ok(())
}

/// Read the eIDAS certificate references from the environment (the
/// per-environment configuration, EU DESIGN.md §5). All four must be
/// present + validly shaped when ANY is set (the pair is a unit); all
/// absent = the deployment runs without the eIDAS trust path (the PIS
/// surface 503s loudly on signature verification, never degrades).
pub fn eidas_refs_from_env() -> Result<Option<EidasCertRefs>, String> {
    let qwac_cert = std::env::var("OPENFIN8_EU_QWAC_CERT_REF").ok();
    let qwac_key = std::env::var("OPENFIN8_EU_QWAC_KEY_REF").ok();
    let qsealc_cert = std::env::var("OPENFIN8_EU_QSEALC_CERT_REF").ok();
    let qsealc_key = std::env::var("OPENFIN8_EU_QSEALC_KEY_REF").ok();
    let present = [
        qwac_cert.is_some(),
        qwac_key.is_some(),
        qsealc_cert.is_some(),
        qsealc_key.is_some(),
    ];
    if present.iter().all(|p| !p) {
        return Ok(None);
    }
    if present.iter().any(|p| !p) {
        return Err("the eIDAS certificate references are a unit: set all four \
             OPENFIN8_EU_{QWAC,QSEALC}_{CERT,KEY}_REF or none"
            .into());
    }
    let refs = EidasCertRefs {
        qwac_cert_ref: qwac_cert.unwrap(),
        qwac_key_ref: qwac_key.unwrap(),
        qsealc_cert_ref: qsealc_cert.unwrap(),
        qsealc_key_ref: qsealc_key.unwrap(),
    };
    for r in [
        &refs.qwac_cert_ref,
        &refs.qwac_key_ref,
        &refs.qsealc_cert_ref,
        &refs.qsealc_key_ref,
    ] {
        validate_secret_ref(r)?;
    }
    Ok(Some(refs))
}

/// The bank-by-bank DCR registration (RFC 7591 with the eIDAS-asserted
/// identity) - one client per (recipient, ASPSP); NO central directory
/// integration (EU DESIGN.md §3 ceremony 1). The registry row lives in
/// `openfin8_eu.recipients` (the recipient tenant's own bookkeeping).
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct DcrRegistration {
    /// The ASPSP-issued client id.
    #[serde(rename = "clientId")]
    pub client_id: String,
    /// The DCR response (the ASPSP's own registration document -
    /// genuinely freeform).
    #[serde(rename = "registrationDocument")]
    pub registration_document: serde_json::Value,
}

/// Build the RFC 7591 DCR request body for an ASPSP's AS: the eIDAS
/// identity rides the TLS handshake (QWAC) + the software assertion;
/// the recipient's redirect URIs carry the XS2A callback form.
pub fn dcr_request_body(
    recipient_name: &str,
    redirect_base: &str,
    scopes: &[String],
) -> serde_json::Value {
    serde_json::json!({
        "client_name": recipient_name,
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "redirect_uris": [format!("{redirect_base}/callback")],
        "token_endpoint_auth_method": "tls_client_auth",
        "scope": scopes.join(" "),
        "software_statement_assertion": "eidas-asserted",
    })
}

/// The QSEALC signature-verification verdict for a payment initiation
/// (EU DESIGN.md §7, EU invariant 1). The verification itself runs at
/// the PIS call site (the resolved QSEALC material + the request's
/// signature); this type is the honest result the handler enforces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
pub enum QsealcVerdict {
    /// The signature verified against the deployment's QSEALC chain.
    Verified,
    /// No signature was presented on a payment initiation.
    Missing,
    /// The signature failed verification (wrong key/tampered body).
    Invalid,
    /// The eIDAS trust path is not configured (PIS fails closed -
    /// never serves an unsigned initiation).
    NotConfigured,
}

/// Pure seam: the enforcement decision for a payment initiation's
/// QSEALC verdict. `NotConfigured` and `Missing` and `Invalid` all
/// REJECT - the payment surface never degrades to serving unsigned
/// initiations (fail-closed, EU DESIGN.md §7).
pub fn enforce_qsealc(verdict: QsealcVerdict) -> Result<(), String> {
    match verdict {
        QsealcVerdict::Verified => Ok(()),
        QsealcVerdict::Missing => {
            Err("payment initiation requires a QSEALC signature (none presented)".into())
        }
        QsealcVerdict::Invalid => Err("the QSEALC signature failed verification".into()),
        QsealcVerdict::NotConfigured => Err(
            "the eIDAS trust path is not configured (set the OPENFIN8_EU_QSEALC_*_REF secret \
             references) - payment initiation fails closed"
                .into(),
        ),
    }
}

/// Pure seam: the QSEALC verification shape over the presented material.
/// A dev-fleet deployment MAY run with the deterministic fixture
/// signature (`sig:<sha256>` over the canonical body) - production rides
/// the resolved QSEALC key (the same seam either way; the fixture never
/// verifies when real material is configured).
pub fn verify_qsealc_fixture(
    signature: Option<&str>,
    canonical_body: &str,
    configured: bool,
) -> QsealcVerdict {
    if !configured {
        return QsealcVerdict::NotConfigured;
    }
    let Some(sig) = signature else {
        return QsealcVerdict::Missing;
    };
    // The fixture form: `sig:<hex-of-sha256(canonical_body)>`.
    let Some(hex) = sig.strip_prefix("sig:") else {
        return QsealcVerdict::Invalid;
    };
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(canonical_body.as_bytes());
    let expected = digest
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    if hex.eq_ignore_ascii_case(&expected) {
        QsealcVerdict::Verified
    } else {
        QsealcVerdict::Invalid
    }
}

/// One recipient's DCR client cache row (per-ASPSP; bank-by-bank).
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct RecipientClient {
    /// The recipient id (the `openfin8_eu.recipients` row).
    pub id: Uuid,
    /// The ASPSP-issued client id.
    #[serde(rename = "clientId")]
    pub client_id: String,
    /// The provider (ASPSP) this client is registered against.
    #[serde(rename = "providerId")]
    pub provider_id: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_refs_are_shape_validated() {
        assert!(validate_secret_ref("sentin8-secrets://qwac-cert").is_ok());
        assert!(validate_secret_ref("secrets://qwac").is_err());
        assert!(validate_secret_ref("sentin8-secrets://").is_err());
        assert!(validate_secret_ref("").is_err());
    }

    #[test]
    fn qsealc_enforcement_fails_closed() {
        assert!(enforce_qsealc(QsealcVerdict::Verified).is_ok());
        for v in [
            QsealcVerdict::Missing,
            QsealcVerdict::Invalid,
            QsealcVerdict::NotConfigured,
        ] {
            assert!(enforce_qsealc(v).is_err(), "{v:?} must reject");
        }
        // The error texts name the fail-closed reason.
        let err = enforce_qsealc(QsealcVerdict::NotConfigured).unwrap_err();
        assert!(err.contains("fails closed"));
    }

    #[test]
    fn qsealc_fixture_verification_shapes() {
        use sha2::{Digest, Sha256};
        let body = r#"{"instructedAmount":{"currency":"EUR","amount":"12.34"}}"#;
        let digest = Sha256::digest(body.as_bytes());
        let sig = format!(
            "sig:{}",
            digest
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        );
        // configured + correct fixture signature -> Verified.
        assert_eq!(
            verify_qsealc_fixture(Some(&sig), body, true),
            QsealcVerdict::Verified
        );
        // configured + wrong body -> Invalid.
        assert_eq!(
            verify_qsealc_fixture(Some(&sig), "tampered", true),
            QsealcVerdict::Invalid
        );
        // configured + no signature -> Missing.
        assert_eq!(
            verify_qsealc_fixture(None, body, true),
            QsealcVerdict::Missing
        );
        // configured + wrong scheme -> Invalid.
        assert_eq!(
            verify_qsealc_fixture(Some("sig:deadbeef"), body, true),
            QsealcVerdict::Invalid
        );
        assert_eq!(
            verify_qsealc_fixture(Some("Bearer xyz"), body, true),
            QsealcVerdict::Invalid
        );
        // not configured -> NotConfigured (regardless of signature).
        assert_eq!(
            verify_qsealc_fixture(Some(&sig), body, false),
            QsealcVerdict::NotConfigured
        );
    }

    #[test]
    fn dcr_body_carries_the_eidas_identity_shape() {
        let body = dcr_request_body(
            "iFinTech",
            "https://openfin8-eu.ops.sys.local.sentin8.dev",
            &["openfin8:eu:accountbasic:read".into()],
        );
        assert_eq!(body["client_name"], "iFinTech");
        assert_eq!(body["token_endpoint_auth_method"], "tls_client_auth");
        assert_eq!(body["software_statement_assertion"], "eidas-asserted");
        assert!(body["redirect_uris"][0]
            .as_str()
            .unwrap()
            .ends_with("/callback"));
    }
}
