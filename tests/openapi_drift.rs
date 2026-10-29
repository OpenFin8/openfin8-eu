// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the OpenFin8:EU
// SPDX-License-Identifier: Apache-2.0

//! OpenAPI coverage drift guard (OAPEC - the router↔spec equality the
//! platform enforces tree-wide; the EU adapter's own surface).
//!
//! Both directions: every SERVED route must be spec'd AND every spec'd
//! path must be served (the OAPEC-1 contract; the published
//! `docs/openapi.json` is the site/API-page source - a served-but-
//! unspec'd route is invisible in the docs, a spec'd-but-unserved path
//! is a lie). The route table is `router::route_table()` - the SAME
//! list `routes()` mounts (a macro keeps the two in lockstep; the test
//! fails LOUDLY on either-direction drift).

use serde_json::Value;
use std::collections::BTreeSet;

/// The (method, path) pairs the router serves - `router::route_table()`
/// is the single source `routes()` itself mounts.
fn served_pairs() -> BTreeSet<(String, String)> {
    openfin8_eu_server::router::route_table()
        .iter()
        .map(|(m, p)| (m.to_string(), p.to_string()))
        .collect()
}

/// The (method, path) pairs the published spec documents.
fn spec_pairs() -> BTreeSet<(String, String)> {
    let text = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/docs/openapi.json"))
        .expect("docs/openapi.json - regenerate via --print-registration --section=openapi");
    let spec: Value = serde_json::from_str(&text).expect("valid JSON");
    let mut pairs = BTreeSet::new();
    let paths = spec
        .pointer("/paths")
        .and_then(Value::as_object)
        .expect("paths object");
    for (path, ops) in paths {
        for (method, op) in ops.as_object().into_iter().flatten() {
            if matches!(method.as_str(), "get" | "post" | "put" | "patch" | "delete")
                && op.is_object()
            {
                pairs.insert((method.to_uppercase(), path.clone()));
            }
        }
    }
    pairs
}

#[test]
fn spec_covers_every_served_route_and_vice_versa() {
    let served = served_pairs();
    let spec = spec_pairs();
    let missing: Vec<_> = served.difference(&spec).collect();
    let stale: Vec<_> = spec.difference(&served).collect();
    assert!(
        missing.is_empty() && stale.is_empty(),
        "router↔spec drift - served-not-spec'd: {missing:?}; spec'd-not-served: {stale:?}"
    );
    // The floor: the XS2A surface's operation count (the Consent API +
    // the ceremonies + PIS + baskets + AIS/PIIS + the extended set).
    assert!(
        spec.len() >= 25,
        "spec floor: expected >= 25 ops for the XS2A surface, got {}",
        spec.len()
    );
}
