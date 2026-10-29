// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the OpenFin8:EU
// SPDX-License-Identifier: Apache-2.0

//! Library target for the openfin8-eu service (the integration
//! tests and the e2e harness link against this; the binary is
//! `src/main.rs`). The XS2A consent + authorisation model lives in
//! `consent.rs`; the routes in `router.rs`; the registration data in
//! `registration.rs` - see DESIGN.md (OBARCH-7).

pub mod consent;
pub mod openapi;
pub mod registration;
pub mod router;
