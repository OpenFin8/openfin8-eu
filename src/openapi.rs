// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the OpenFin8:EU
// SPDX-License-Identifier: Apache-2.0

//! OpenAPI spec for OpenFin8:EU.
//!
//! The VENDORED case: the Berlin Group openFinance
//! OpenAPI files are published under Creative Commons Attribution 4.0
//! (CC BY 4.0) - the licence notice explicitly permits copying and
//! adaptation with attribution - so this adapter MAY carry the
//! openFinance resource paths in its published spec **with the BG
//! attribution preserved** (the *Implementation Guidelines*
//! documents are CC BY-ND and are never copied; the normative
//! reference remains them). The utoipa aggregate carries the
//! openFinance resource annotations, and the notice travels in the
//! spec's info block.
//!
//! The drift guard (`tests/openapi_publication.rs`) asserts the
//! attribution is present and that no other standard's surface
//! leaks in (`/fdx/`, `/open-banking/`) - the inverse of the
//! US/CA policy.

use utoipa::OpenApi;

/// The Berlin Group openFinance attribution notice that MUST accompany
/// any copied openFinance OpenAPI material. Rendered into the published
/// spec's info block - wired into the utoipa description when the XS2A
/// paths land); the drift guard tests against the marker
/// string.
#[allow(dead_code)]
pub const BG_OPENFINANCE_NOTICE: &str =
    "The Berlin Group openFinance OpenAPI files are published under \
Creative Commons Attribution 4.0 (CC BY 4.0); resource paths here \
derive from them with the attribution preserved. The normative \
reference remains the Implementation Guidelines.";

/// OpenFin8:EU OpenAPI surface: OpenFin8-owned routes plus (as the
/// XS2A wire lands) the Berlin Group openFinance resource paths under
/// the CC BY 4.0 attribution notice.
#[derive(OpenApi)]
#[openapi(
    info(
        title = "openfin8-eu",
        description = "Sentin8 OpenFin8:EU - European open finance (Berlin Group \
openFinance V2: AIS/PIS/PIIS over XS2A, the three SCA approaches, \
eIDAS QWAC/QSEALC certificates, signing baskets). The openFinance \
OpenAPI files are published under Creative Commons Attribution 4.0 \
(CC BY 4.0); resource paths carried with the attribution preserved. \
The normative reference remains the Implementation Guidelines.",
        license(name = "MIT OR Apache-2.0", identifier = "MIT OR Apache-2.0"),
        version = "0.1.0"
    ),
    paths(
        crate::consent::create_consent,
        crate::consent::get_consent,
        crate::consent::get_consent_status,
        crate::consent::start_authorisation,
        crate::consent::list_authorisations,
        crate::consent::get_authorisation,
        crate::ceremony::start_redirect,
        crate::ceremony::redirect_callback,
        crate::ceremony::start_decoupled,
        crate::ceremony::poll_decoupled,
        crate::ceremony::start_embedded,
        crate::ceremony::answer_embedded,
        crate::ceremony::execute_step_handler,
        crate::payments::create_payment,
        crate::payments::get_payment_status,
        crate::payments::cancel_payment,
        crate::payments::create_basket,
        crate::payments::get_basket,
        crate::ais::get_accounts,
        crate::ais::get_balances,
        crate::ais::get_transactions,
        crate::ais::get_card_accounts,
        crate::ais::confirm_funds,
        crate::extended::discovery,
        crate::extended::list_mandates,
        crate::extended::list_request_to_pay,
        crate::extended::list_push_ais,
        crate::extended::download_document,
    ),
    components(schemas(
        crate::consent::CreateConsentRequest,
        crate::consent::ConsentResponse,
        crate::consent::ConsentStatusResponse,
        crate::consent::StartAuthorisationRequest,
        crate::consent::AuthorisationResponse,
        crate::consent::AuthorisationListResponse,
        crate::ceremony::RedirectStartResponse,
        crate::ceremony::RedirectCallbackRequest,
        crate::ceremony::DecoupledStatusResponse,
        crate::ceremony::EmbeddedChallengeResponse,
        crate::ceremony::EmbeddedAnswerRequest,
        crate::ceremony::ProxyBackRequest,
        crate::ceremony::ProxyBackResponse,
        crate::payments::CreatePaymentRequest,
        crate::payments::PaymentResponse,
        crate::payments::CreateBasketRequest,
        crate::payments::BasketResponse,
        crate::ais::AccountsPassthrough,
        crate::ais::FundsConfirmationRequest,
        crate::ais::FundsConfirmationResponse,
        crate::extended::DiscoveryResponse,
        crate::extended::UnsupportedResponse,
    )),
    security()
)]
pub struct EUOpenApi;
