// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the OpenFin8:EU
// SPDX-License-Identifier: Apache-2.0

//! Sentin8 OpenFin8:EU - European open finance: the Berlin Group openFinance API
//! Framework V2 (the NextGenPSD2 successor) - AIS/PIS/PIIS with
//! the SCA approaches (redirect/decoupled/embedded), eIDAS
//! QWAC/QSEALC certificates, consent authorisation pre-steps, and
//! signing baskets. See
//! `DESIGN.md`.
//!
//! This service embeds `openfin8-core` (the jurisdiction-agnostic
//! kernel) and supplies the EU profile, the XS2A ceremony (bank-by-bank DCR + eIDAS
//! certs + the three SCA approaches), and the openFinance V2
//! resource router. See `DESIGN.md` §2-§5 for the wire, the
//! ceremonies, and the served surface.
//!
//! Spec publication is the vendored-with-attribution case:
//! the Berlin Group OpenAPI files are CC BY 4.0 (copying and
//! adaptation permitted with attribution), so the published
//! `docs/openapi.json` MAY carry the openFinance resource paths
//! with the attribution preserved (see `src/openapi.rs`).

use utoipa::OpenApi;

use openfin8_eu_server::{openapi, registration, router};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    sentin8::shell::serve(
        sentin8::shell::Sentin8Shell::new("openfin8:eu", "OPENFIN8_EU")
            .with_registration(registration::print)
            .with_own_health()
            .with_state(router::build_state)
            .with_router(router::routes)
            .with_openapi(openapi::EUOpenApi::openapi()),
    )
    .await
}
