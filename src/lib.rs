// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the OpenFin8:EU
// SPDX-License-Identifier: Apache-2.0

//! Library target for the openfin8-eu service (the integration
//! tests and the e2e harness link against this; the binary is
//! `src/main.rs`). The XS2A consent + authorisation model lives in
//! `consent.rs`; the SCA ceremonies in `ceremony.rs`; the eIDAS + DCR
//! trust path in `eidas.rs`; PIS + signing baskets in `payments.rs`;
//! the AIS/PIIS surfaces in `ais.rs`; the Extended Services in
//! `extended.rs`; the routes in `router.rs`; the registration data in
//! `registration.rs` - see DESIGN.md).

pub mod ais;
pub mod ceremony;
pub mod consent;
pub mod eidas;
pub mod extended;
pub mod openapi;

// The utoipa dump for registration::print - mirrored from main.rs; the
// lib crate compiles registration::print too (test harnesses embedding
// via #[path] never invoke it, so the pointer is referenced, not run).
#[cfg_attr(test, allow(dead_code))]
static OPENAPI_DUMP: fn() -> serde_json::Value = || {
    use utoipa::OpenApi as _;
    serde_json::to_value(openapi::EUOpenApi::openapi()).unwrap_or(serde_json::Value::Null)
};

pub mod payments;
pub mod registration;
pub mod router;
