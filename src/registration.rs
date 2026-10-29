// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the OpenFin8:EU
// SPDX-License-Identifier: Apache-2.0

//! Service self-registration data for OpenFin8:EU (OBARCH-7).
//! Output via `--print-registration` flag. See `sentin8/design/sentin8-service-self-registration-design.md`.
//!
//! The shape follows the `openfin8-ca` registration (the per-jurisdiction
//! identity): PG role `openfin8_eu_service` on the `openfin8` vertical
//! database, the EU scope vocabulary `openfin8:eu:*`, the served-SCA
//! honest configuration, and the scope-mirror policy set seeded by
//! `vertical enroll`.

use sentin8::registration::{
    AdminScope, AdminUi, AdminUiPage, AuditFinding, ErrorCode, M2mGrant, PgRole, PolicySetDecl,
    Registration, RelationDecl, ServiceActionEntry, SqlMigration,
};
use utoipa::OpenApi;

const PG_ROLES: &[PgRole] = &[PgRole {
    scope: "openfin8:eu:read,openfin8:eu:write",
    role: "openfin8_eu_service",
    bypass_rls: false,
    // Grants live in the openfin8 vertical database only (DBX §6.6
    // database-per-vertical, schema-per-service).
    database: "openfin8",
    // The EU adapter owns all its reads - no cross-schema grants.
    cross_schema_grants: &[],
}];

/// M2M scope grants (CERTFREE-4V: the TLS client certificate IS the
/// identity; `vertical enroll` upserts the registry map from these rows).
/// The workload names follow the CA adapter's precedent (colon identity +
/// the dash short form the runtime call sites pass).
const M2M_GRANTS: &[M2mGrant] = &[
    // The service's own workload: bus produce/consume + stat + flow.
    M2mGrant {
        workload: "openfin8:eu",
        scopes: &[
            "sentin8:bus:produce",
            "sentin8:bus:consume",
            "sentin8:stat:measure",
            "sentin8:flow:write",
        ],
    },
    M2mGrant {
        workload: "openfin8-eu",
        scopes: &[
            "sentin8:bus:produce",
            "sentin8:bus:consume",
            "sentin8:stat:measure",
            "sentin8:flow:write",
        ],
    },
    // Shell audit-journal pusher workload (audit crate §6.8; boot step 8c).
    M2mGrant {
        workload: "openfin8-eu-audit",
        scopes: &["sentin8:sys:audit:write"],
    },
    // Shield hot-reload consumer (policy_bus_client).
    M2mGrant {
        workload: "openfin8-eu-policy",
        scopes: &["sentin8:bus:consume", "sentin8:stat:measure"],
    },
    // VDC-4 tenant-snapshot API workload: the env-init consumer fetches
    // tenant identity for issuer/callback derivation.
    M2mGrant {
        workload: "openfin8-eu-sys",
        scopes: &["sentin8:sys:tenants:read"],
    },
    // TLS-RLS-4: the database-free HostContextResolver's resolve workload.
    M2mGrant {
        workload: "openfin8-eu-tls",
        scopes: &["sentin8:sys:instances:read"],
    },
];

const ADMIN_SCOPES: &[AdminScope] = &[
    AdminScope::Typed {
        role: "openfin8:eu:admin",
        scope: "openfin8:eu:consents:write",
    },
    AdminScope::Typed {
        role: "openfin8:eu:admin",
        scope: "openfin8:eu:consents:read",
    },
    AdminScope::Typed {
        role: "openfin8:eu:admin",
        scope: "openfin8:eu:recipient:read",
    },
    AdminScope::Typed {
        role: "openfin8:eu:admin",
        scope: "openfin8:eu:recipient:write",
    },
    AdminScope::Typed {
        role: "openfin8:eu:admin",
        scope: "openfin8:eu:provider:write",
    },
    AdminScope::Typed {
        role: "openfin8:eu:admin",
        scope: "openfin8:eu:provider:read",
    },
    AdminScope::Typed {
        role: "openfin8:eu:admin",
        scope: "openfin8:eu:policy:read",
    },
    AdminScope::Typed {
        role: "openfin8:eu:admin",
        scope: "openfin8:eu:policy:write",
    },
];

const ERROR_CODES: &[ErrorCode] = &[
    ErrorCode {
        enum_name: "EuConsentInvalid",
        error_code: "eu_consent_invalid",
        status_code: 403,
    },
    ErrorCode {
        enum_name: "EuConsentRevoked",
        error_code: "eu_consent_revoked",
        status_code: 403,
    },
    ErrorCode {
        enum_name: "EuScaApproachNotServed",
        error_code: "eu_sca_approach_not_served",
        status_code: 400,
    },
];

const ADMIN_UI_PAGES: &[AdminUiPage] = &[
    AdminUiPage {
        route: "overview",
        label: "Overview",
        ui_endpoint: "/v1/admin/ui/overview",
        data_endpoint: "/v1/admin/overview",
        icon: "0xe1b1",
    },
    AdminUiPage {
        route: "consents",
        label: "Consents",
        ui_endpoint: "/v1/admin/ui/consents",
        data_endpoint: "/v1/admin/consents",
        icon: "0xe69a",
    },
    AdminUiPage {
        route: "authorisations",
        label: "Authorisations",
        ui_endpoint: "/v1/admin/ui/authorisations",
        data_endpoint: "/v1/admin/authorisations",
        icon: "0xe8f4",
    },
    AdminUiPage {
        route: "settings",
        label: "Settings",
        ui_endpoint: "/v1/admin/ui/settings",
        data_endpoint: "/v1/admin/settings",
        icon: "0xe57f",
    },
];

/// Default declarative policy set (the scope-mirror shape; seeded by
/// `vertical enroll` as `origin='platform'`, `mode='enforced'`):
/// action-granular scope permits over the LIVE effective scope set -
/// the exact mirror of the gates this service's handlers evaluate.
const SCOPE_MIRROR_POLICIES: &str = "permit(principal, action == Action::\"openfin8:eu:consents:read\", resource) when { principal.scopes.contains(\"openfin8:eu:admin\") };\npermit(principal, action == Action::\"openfin8:eu:consents:read\", resource) when { principal.scopes.contains(\"openfin8:eu:consents:read\") };\npermit(principal, action == Action::\"openfin8:eu:consents:read\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };\npermit(principal, action == Action::\"openfin8:eu:consents:read\", resource) when { principal.scopes.contains(\"sentin8:sys:org:admin\") };\npermit(principal, action == Action::\"openfin8:eu:consents:read\", resource) when { principal.scopes.contains(\"sentin8:sys:env:admin\") };\npermit(principal, action == Action::\"openfin8:eu:consents:write\", resource) when { principal.scopes.contains(\"openfin8:eu:consents:write\") };\npermit(principal, action == Action::\"openfin8:eu:consents:write\", resource) when { principal.scopes.contains(\"openfin8:eu:admin\") };\npermit(principal, action == Action::\"openfin8:eu:consents:write\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };\npermit(principal, action == Action::\"openfin8:eu:consents:write\", resource) when { principal.scopes.contains(\"sentin8:sys:org:admin\") };\npermit(principal, action == Action::\"openfin8:eu:consents:write\", resource) when { principal.scopes.contains(\"sentin8:sys:env:admin\") };\npermit(principal, action == Action::\"openfin8:eu:recipient:read\", resource) when { principal.scopes.contains(\"openfin8:eu:recipient:read\") };\npermit(principal, action == Action::\"openfin8:eu:recipient:read\", resource) when { principal.scopes.contains(\"openfin8:eu:admin\") };\npermit(principal, action == Action::\"openfin8:eu:recipient:read\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };\npermit(principal, action == Action::\"openfin8:eu:recipient:write\", resource) when { principal.scopes.contains(\"openfin8:eu:recipient:write\") };\npermit(principal, action == Action::\"openfin8:eu:recipient:write\", resource) when { principal.scopes.contains(\"openfin8:eu:admin\") };\npermit(principal, action == Action::\"openfin8:eu:recipient:write\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };\npermit(principal, action == Action::\"openfin8:eu:provider:read\", resource) when { principal.scopes.contains(\"openfin8:eu:provider:read\") };\npermit(principal, action == Action::\"openfin8:eu:provider:read\", resource) when { principal.scopes.contains(\"openfin8:eu:admin\") };\npermit(principal, action == Action::\"openfin8:eu:provider:read\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };\npermit(principal, action == Action::\"openfin8:eu:provider:write\", resource) when { principal.scopes.contains(\"openfin8:eu:provider:write\") };\npermit(principal, action == Action::\"openfin8:eu:provider:write\", resource) when { principal.scopes.contains(\"openfin8:eu:admin\") };\npermit(principal, action == Action::\"openfin8:eu:provider:write\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };\npermit(principal, action == Action::\"openfin8:eu:policy:read\", resource) when { principal.scopes.contains(\"openfin8:eu:policy:read\") };\npermit(principal, action == Action::\"openfin8:eu:policy:read\", resource) when { principal.scopes.contains(\"openfin8:eu:admin\") };\npermit(principal, action == Action::\"openfin8:eu:policy:read\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };\npermit(principal, action == Action::\"openfin8:eu:policy:write\", resource) when { principal.scopes.contains(\"openfin8:eu:policy:write\") };\npermit(principal, action == Action::\"openfin8:eu:policy:write\", resource) when { principal.scopes.contains(\"openfin8:eu:admin\") };\npermit(principal, action == Action::\"openfin8:eu:policy:write\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };\n";

const POLICIES: &[PolicySetDecl] = &[PolicySetDecl {
    policy_set_name: "scope-mirror",
    description: "Action-granular scope permits for openfin8:eu over the LIVE effective scope set (design §3.1d). Step 5 is the only gate.",
    // Shield text lives in SCOPE_MIRROR_POLICIES (single source).
    policies: SCOPE_MIRROR_POLICIES,
    schema: None,
    mode: "enforced",
    default_enabled: true,
}];

/// Default ReBAC relation tuples - none declared; env admins author their
/// own graph via the relations admin API.
const RELATIONS: &[RelationDecl] = &[];

const SQL_1_INIT: &str = include_str!("../sql/init.sql");

const AUDIT_FINDINGS: &[AuditFinding] = &[
    AuditFinding {
        finding: "Integration credentials stored without a secret reference",
        recommendation: "eIDAS QWAC/QSEALC certificate pairs and any third-party credential must be stored as a sentin8-secrets:// reference. The sentin8-secrets crate resolves the reference to the actual value at runtime.",
    },
];

const SERVICE_ACTIONS: &[ServiceActionEntry] = &[ServiceActionEntry {
    action: "eu_consent_start",
    service_type: "openfin8:eu",
    platform_domain_key: "openfin8:eu",
    method: "POST",
    endpoint: "/v1/recipient/consents/start",
    scope: "openfin8:eu:recipient:write",
}];

/// Consent data provider consumed by Sentin8:Auth's accounts proxy
/// (`WHERE feature='openfin8-eu' AND data_type='accounts'`, design §4.3b).
fn consent_providers_json() -> Vec<serde_json::Value> {
    vec![serde_json::json!({
        "feature": "openfin8-eu",
        "data_type": "accounts",
        "service_type": "openfin8:eu",
        "platform_domain_key": "openfin8:eu",
        "endpoint": "/v1/auth/consent/accounts",
        "scope": "openfin8:eu:consents:read",
        "response_key": "accounts"
    })]
}

/// Consent flow declaring the XS2A consent RFW surface (design §4.3b).
fn consent_flows_json() -> Vec<serde_json::Value> {
    vec![serde_json::json!({
        "id": "eu_xs2a_data_sharing",
        "trigger_patterns": ["openfin8:eu:recipient:*"],
        "service_type": "openfin8:eu",
        "ui_endpoint": "/v1/auth/consent/ui",
        "approve_endpoint": "/v1/auth/consent/approve",
        "deny_endpoint": "/v1/auth/consent/deny"
    })]
}

fn openapi_spec() -> serde_json::Value {
    serde_json::to_value(crate::openapi::EUOpenApi::openapi()).unwrap_or(serde_json::Value::Null)
}

/// Print the registration JSON to stdout.
pub fn print(section: Option<String>) -> anyhow::Result<()> {
    // Leak the two small JSON arrays to satisfy the `'static` field type
    // bounded, one-time allocation per process.
    let consent_providers: &'static [serde_json::Value] =
        Box::leak(consent_providers_json().into_boxed_slice());
    let consent_flows: &'static [serde_json::Value] =
        Box::leak(consent_flows_json().into_boxed_slice());
    let reg = Registration {
        service_type: "openfin8:eu",
        subdomain: "openfin8-eu",
        health_path: "/v1/health",
        admin_scopes: ADMIN_SCOPES,
        error_codes: ERROR_CODES,
        consent_providers,
        consent_flows,
        policies: POLICIES,
        relations: RELATIONS,
        event_triggers: &[],
        schedules: &[],
        admin_ui: Some(AdminUi {
            label: "OpenEU",
            icon: "0xe8f4",
            service_flag: "openfin8-eu",
            pages: ADMIN_UI_PAGES,
        }),
        sql_migrations: vec![SqlMigration {
            version: 1,
            name: "init",
            sql: SQL_1_INIT,
        }],
        audit_findings: Some(AUDIT_FINDINGS),
        service_actions: Some(SERVICE_ACTIONS),
        m2m_grants: Some(M2M_GRANTS),
        pg_roles: PG_ROLES,
        openapi_url: "/openapi.json",
        openapi: openapi_spec,
    };
    sentin8::registration::print_registration(section, &reg, openapi_spec)
}