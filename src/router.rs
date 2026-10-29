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
//! routes (the four-state consent machine + the authorisation
//! sub-resources + the pre-step) live here. The AIS/PIS/PIIS resource
//! surfaces (EU-6), the SCA ceremony routes (EU-3), and the payments
//! proxy lanes (EU-5) mount onto this router as they land.

use axum::routing::{get, post};
use openfin8_core::profile::Profile;

use crate::consent::{self, AppState};

/// Build the EU application state from the shell's core.
pub async fn build_state(core: sentin8::shell::ServiceCore) -> anyhow::Result<AppState> {
    let profile = Profile::european_union();
    Ok(AppState::from_env(core.pool.clone(), profile))
}

/// The EU routes: the Consent API surface (adapter-owned XS2A).
pub fn routes(
    router: axum::Router<AppState>,
    state: AppState,
) -> axum::Router<AppState> {
    router
        // The Consent API: the four-state consent machine + the
        // authorisation sub-resources (the pre-step).
        .route(
            "/v1/consents",
            post(consent::create_consent),
        )
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
        .with_state(state)
}