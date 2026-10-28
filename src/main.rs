// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the OpenFin8:EU
// SPDX-License-Identifier: Apache-2.0

//! Sentin8 OpenFin8:EU - European open finance: the Berlin Group openFinance API
//! Framework V2 (the NextGenPSD2 successor) - AIS/PIS/PIIS with
//! the SCA approaches (redirect/decoupled/embedded), eIDAS
//! QWAC/QSEALC certificates, consent authorisation pre-steps, and
//! signing baskets. See
//! `DESIGN.md` (OBARCH-7).
//!
//! This service embeds `openfin8-core` (the jurisdiction-agnostic
//! kernel - OBARCH-1) and supplies the EU profile, the XS2A ceremony (bank-by-bank DCR + eIDAS
//! certs + the three SCA approaches), and the openFinance V2
//! resource router.
//!
//! Skeleton - the OBARCH-1 core extraction lands first; this binary
//! then takes the OB wire handlers, the intent-based consent model
//! over core's `awaiting_authorization` state, and its registration
//! data. Auth gains the FAPI 1 Advanced profile flag alongside
//! (sequenced with this adapter).
//!
//! Spec publication (OBARCH-2) is the vendored-with-attribution case:
//! the Berlin Group OpenAPI files are CC BY 4.0 (copying and
//! adaptation permitted with attribution), so the published
//! `docs/openapi.json` MAY carry the openFinance resource paths
//! with the attribution preserved (see `src/openapi.rs`).

use utoipa::OpenApi;

mod openapi;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    sentin8::shell::serve(
        sentin8::shell::Sentin8Shell::new("openfin8:eu", "OPENFIN8_EU")
            .with_registration(print_registration_stub)
            .with_own_health()
            .with_openapi(openapi::EUOpenApi::openapi()),
    )
    .await
}

/// Registration stub - the full registration data (policy sets,
/// Shield gates `openfin8:eu:*` role-scoped, admin UI pages, SQL
/// migrations, the staged-intent expiry schedule) lands with the
/// OBARCH-1 extraction; the shape follows the `openfin8-us`
/// registration (per-jurisdiction identity).
fn print_registration_stub(section: Option<String>) -> anyhow::Result<()> {
    // Placeholder until the registration module lands (OBARCH-7).
    let _ = section;
    Ok(())
}
