-- SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
-- SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
-- SPDX-FileCopyrightText: Copyright Contributors to the OpenFin8:EU
-- SPDX-License-Identifier: Apache-2.0

-- OpenFin8:EU - the service's own schema `openfin8_eu` (schema-per-service):
-- openfin8_eu_* domain tables + openfin8_eu.outbox / openfin8_eu.audit_journal
-- producer tables, all FORCE-RLS env-scoped (provider_profiles is the public
-- cross-env catalog - no RLS by design, the CA v2 convergence).
--
-- THE XS2A CONSENT-AUTHORISATION MODEL (openfin8-eu DESIGN.md §3): unlike
-- the FDX single-grant shape, an XS2A consent carries explicit
-- AUTHORISATION SUB-RESOURCES - each SCA ceremony is its own object,
-- tracked separately from the consent grant. The consent itself rides the
-- kernel's `awaiting_authorization` state (XS2A `received`) -> `active`
-- (`valid`) -> `revoked`/`expired` (with `rejected` on the deny path) -
-- the four-state XS2A consent machine. SCA success is NEVER conflated
-- with consent grant: two separate state machines, the authorisation
-- machine per-approach.
--
-- TWO LEDGERS (openfin8 DESIGN.md §3, unchanged): the provider's GRANT
-- ledger (`openfin8_eu.consents` - seeded from sentin8:auth:grant:created)
-- lives in the provider tenant; the recipient's REGISTRY
-- (`openfin8_eu.recipient_consents` + `openfin8_eu.recipients`) lives in
-- the recipient tenant. The OAuth client belongs to the recipient. No
-- column on one side's tables references the other side's tenant identity
-- beyond opaque OAuth handles.

CREATE SCHEMA IF NOT EXISTS openfin8_eu;

-- ── The PROVIDER grant ledger: the XS2A consent ──────────────────────
-- The four-state XS2A consent machine over the kernel's states:
--   received   <- created, awaiting authorization (kernel awaiting_authorization)
--   valid      <- all authorisations complete (kernel active)
--   rejected   <- the PSU denied the grant (kernel revoked, deny path)
--   expired    <- the consent's validity window elapsed (kernel expired)
CREATE TABLE IF NOT EXISTS openfin8_eu.consents (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id          UUID NOT NULL,
    customer_id     UUID NOT NULL,
    recipient_id    TEXT,
    provider_id     TEXT,
    provider_name   TEXT,
    -- The XS2A consent state: received | valid | rejected | expired
    -- (+ revoked when the grant is terminated early - terminal, the
    -- kernel's revocation is always terminal).
    status          TEXT NOT NULL DEFAULT 'received'
                    CHECK (status IN ('received', 'valid', 'rejected', 'expired', 'revoked')),
    -- The XS2A service: AIS | PIS | PIIS (the consent resource family).
    service         TEXT NOT NULL CHECK (service IN ('ais', 'pis', 'piis')),
    -- The requested OAuth scopes (the XS2A scope vocabulary).
    scopes          TEXT[] NOT NULL DEFAULT '{}',
    -- The XS2A frequency-per-day (AIS: repeated access cadence; absent
    -- = one-shot access).
    frequency_per_day   INTEGER,
    -- The AIS transaction lookback window (days from grant).
    lookback_days       INTEGER,
    -- The combined expiry: XS2A consents expire 90 days max (AIS);
    -- absent = no expiry.
    expires_at      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_openfin8_eu_consents_env ON openfin8_eu.consents (env_id);
CREATE INDEX IF NOT EXISTS idx_openfin8_eu_consents_customer ON openfin8_eu.consents (customer_id);
CREATE INDEX IF NOT EXISTS idx_openfin8_eu_consents_status ON openfin8_eu.consents (status);

-- ── The AUTHORISATION SUB-RESOURCES (the XS2A pre-step) ─────────────
-- Each SCA ceremony is its own object under the consent (DESIGN.md §3.4):
-- created via the pre-step (`startAuthorisation`, optionally selecting
-- the SCA approach BEFORE the PSU ceremony begins), then driven through
-- its own per-approach state machine by the Flow ceremonies.
-- Separation of state machines (DESIGN.md §7): an authorisation reaching
-- FINALISED never mutates the consent's status directly - the consent
-- transitions when the adapter observes the authorisation outcome.
CREATE TABLE IF NOT EXISTS openfin8_eu.consent_authorisations (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id          UUID NOT NULL,
    consent_id      UUID NOT NULL REFERENCES openfin8_eu.consents(id) ON DELETE CASCADE,
    -- The per-approach authorisation state machine (XS2A):
    --   received     <- created by the pre-step, awaiting PSU ceremony
    --   psu_identified / psu_authenticated <- progress markers
    --   sca_started  <- the SCA challenge issued (approach-specific)
    --   finalised    <- SCA succeeded (the consent may transition)
    --   failed       <- SCA failed or was denied (attempt-exhausted)
    --   expired      <- the authorisation window elapsed
    status          TEXT NOT NULL DEFAULT 'received'
                    CHECK (status IN ('received', 'psu_identified', 'psu_authenticated',
                                      'sca_started', 'finalised', 'failed', 'expired')),
    -- The SCA approach this ceremony runs: redirect (mandatory) |
    -- decoupled | embedded (conditional per the RTS exemptions; the
    -- served list is honest per-environment configuration).
    approach        TEXT NOT NULL DEFAULT 'redirect'
                    CHECK (approach IN ('redirect', 'decoupled', 'embedded')),
    -- The PSU identity once identified (the bank customer's sub).
    psu_id          TEXT,
    -- The Flow execution id driving this ceremony (
    -- per-approach step sequences; absent = not yet started).
    flow_execution_id UUID,
    -- The ceremony's own expiry (the XS2A authorisation window).
    expires_at      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_openfin8_eu_auths_consent
    ON openfin8_eu.consent_authorisations (consent_id);
CREATE INDEX IF NOT EXISTS idx_openfin8_eu_auths_env ON openfin8_eu.consent_authorisations (env_id);
CREATE INDEX IF NOT EXISTS idx_openfin8_eu_auths_status ON openfin8_eu.consent_authorisations (status);

-- ── The signing-basket batch authorization (a distinct EU concept) ────
-- One PSU ceremony authorizing multiple consents + payments (DESIGN.md
-- §2): the basket is its own object; its authorisation sub-resource is
-- the shared SCA ceremony; the member rows ride consent_id (NULL for
-- payment-only members - payments join by their own ids).
CREATE TABLE IF NOT EXISTS openfin8_eu.signing_baskets (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id          UUID NOT NULL,
    customer_id     UUID NOT NULL,
    -- received | valid | rejected | expired (the basket's own XS2A state).
    status          TEXT NOT NULL DEFAULT 'received'
                    CHECK (status IN ('received', 'valid', 'rejected', 'expired')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS openfin8_eu.signing_basket_items (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    basket_id       UUID NOT NULL REFERENCES openfin8_eu.signing_baskets(id) ON DELETE CASCADE,
    -- The batched consent (or NULL when the item is payment-only).
    consent_id      UUID REFERENCES openfin8_eu.consents(id),
    -- The batched payment's own id (the PIS payment resource; joined by
    -- the payments surface joining the ISO payment products).
    payment_id      TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_openfin8_eu_basket_items_basket
    ON openfin8_eu.signing_basket_items (basket_id);

-- ── The RECIPIENT registry (the recipient tenant's own bookkeeping) ──
-- The two-ledger model: the recipient keeps its own consent registry;
-- the OAuth client belongs to the recipient. Written by the
-- recipient-side consent-start/callback; no cross-tenant SQL ever.
CREATE TABLE IF NOT EXISTS openfin8_eu.recipients (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id          UUID NOT NULL,
    -- The recipient's display name (the fintech).
    name            TEXT NOT NULL,
    -- The DCR-registered OAuth client id at the provider's AS
    -- (bank-by-bank: per (recipient env, provider)).
    client_id       TEXT NOT NULL,
    -- The provider this recipient is registered against (opaque handle).
    provider_id     TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'active'
                    CHECK (status IN ('active', 'suspended')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (env_id, client_id, provider_id)
);

CREATE INDEX IF NOT EXISTS idx_openfin8_eu_recipients_env ON openfin8_eu.recipients (env_id);

CREATE TABLE IF NOT EXISTS openfin8_eu.recipient_consents (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id          UUID NOT NULL,
    -- The recipient's own customer (the fintech's user).
    customer_id     UUID NOT NULL,
    provider_id     TEXT NOT NULL,
    provider_name   TEXT,
    -- Mirrors the provider-side XS2A consent state as the recipient
    -- observes it (pending until the callback lands).
    status          TEXT NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending', 'received', 'valid', 'rejected', 'expired', 'revoked')),
    scopes          TEXT[] NOT NULL DEFAULT '{}',
    -- The PSU-selected account ids (opaque handles at the recipient).
    selected_account_ids TEXT[] NOT NULL DEFAULT '{}',
    -- Token references (secret references only - never key material).
    token_ref       TEXT,
    refresh_ref     TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_openfin8_eu_rcpt_consents_env ON openfin8_eu.recipient_consents (env_id);
CREATE INDEX IF NOT EXISTS idx_openfin8_eu_rcpt_consents_customer ON openfin8_eu.recipient_consents (customer_id);

-- ── The provider catalog (the public cross-env registry - NO RLS by
-- design; the CA v2 convergence: the recipient plane lists providers
-- across envs, so the tenant-visibility policies must not apply).
CREATE TABLE IF NOT EXISTS openfin8_eu.provider_profiles (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id          UUID NOT NULL,
    provider_name   TEXT NOT NULL,
    issuer_url      TEXT NOT NULL,
    -- The Berlin Group openFinance version this ASPSP serves.
    of_version      TEXT NOT NULL DEFAULT '2.4',
    -- The SCA approaches this ASPSP serves (the honest per-env list;
    -- redirect is mandatory and always present).
    sca_approaches  TEXT[] NOT NULL DEFAULT '{redirect}'
                    CHECK ('redirect' = ANY (sca_approaches)),
    status          TEXT NOT NULL DEFAULT 'active',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (env_id, provider_name)
);

-- ── The producer tables (the platform contract: outbox + audit) ──────
-- The local outbox (the SDK's full-column shape - the contract every
-- init.sql mirrors): one row per emitted event, drained by the shell's
-- relay (boot step 8b) to Bus with `openfin8-eu` family frames.
CREATE TABLE IF NOT EXISTS openfin8_eu.outbox (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id          UUID NOT NULL,
    event_type      TEXT NOT NULL,
    payload         JSONB NOT NULL DEFAULT '{}',
    idempotency_key TEXT,
    stream_family   TEXT NOT NULL DEFAULT 'openfin8-eu',
    publisher_service TEXT NOT NULL DEFAULT 'openfin8:eu',
    relayed         BOOLEAN NOT NULL DEFAULT FALSE,
    relay_attempts  INTEGER NOT NULL DEFAULT 0,
    next_retry_at   TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_openfin8_eu_outbox_unrelayed
    ON openfin8_eu.outbox (relayed, next_retry_at)
    WHERE NOT relayed;

-- The audit journal (the canonical 15-column shape).
CREATE TABLE IF NOT EXISTS openfin8_eu.audit_journal (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id          UUID NOT NULL,
    target_resource_type  TEXT,
    target_resource_id    TEXT,
    actor_user_id         TEXT,
    actor_subject_type    TEXT,
    severity        TEXT NOT NULL DEFAULT 'info',
    correlation_id  TEXT,
    before_state    JSONB,
    after_state     JSONB,
    details         JSONB,
    pushed          BOOLEAN NOT NULL DEFAULT FALSE,
    pushed_at       TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_openfin8_eu_audit_unpushed
    ON openfin8_eu.audit_journal (pushed)
    WHERE NOT pushed;

-- ── RLS: FORCE on every tenant-scoped table; env_id-pinned policies ──
DO $$
DECLARE
    t TEXT;
BEGIN
    FOREACH t IN ARRAY ARRAY[
        'consents', 'consent_authorisations', 'signing_baskets',
        'signing_basket_items', 'recipients', 'recipient_consents'
    ]
    LOOP
        EXECUTE format('ALTER TABLE openfin8_eu.%I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE openfin8_eu.%I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format('DROP POLICY IF EXISTS %I ON openfin8_eu.%I', t || '_dml', t);
        EXECUTE format(
            'CREATE POLICY %I ON openfin8_eu.%I FOR ALL
             USING (env_id = sentin8_current_env_id() OR sentin8_is_env_admin())
             WITH CHECK (env_id = sentin8_current_env_id() OR sentin8_is_env_admin())',
            t || '_dml', t);
    END LOOP;
END $$;

-- The outbox/audit producer tables: the relay/pusher workloads run as the
-- service role with the env stamped in the tenant context (the platform
-- contract); same env-pinned shape.
DO $$
DECLARE
    t TEXT;
BEGIN
    FOREACH t IN ARRAY ARRAY['outbox', 'audit_journal']
    LOOP
        EXECUTE format('ALTER TABLE openfin8_eu.%I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE openfin8_eu.%I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format('DROP POLICY IF EXISTS %I ON openfin8_eu.%I', t || '_dml', t);
        EXECUTE format(
            'CREATE POLICY %I ON openfin8_eu.%I FOR ALL
             USING (env_id = sentin8_current_env_id() OR sentin8_is_env_admin())
             WITH CHECK (env_id = sentin8_current_env_id() OR sentin8_is_env_admin())',
            t || '_dml', t);
    END LOOP;
END $$;

-- provider_profiles: the public cross-env catalog - NO RLS (the CA v2
-- convergence; the drift guard pins it).
ALTER TABLE openfin8_eu.provider_profiles NO FORCE ROW LEVEL SECURITY;
ALTER TABLE openfin8_eu.provider_profiles DISABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS provider_profiles_select ON openfin8_eu.provider_profiles;
DROP POLICY IF EXISTS provider_profiles_insert ON openfin8_eu.provider_profiles;
DROP POLICY IF EXISTS provider_profiles_update ON openfin8_eu.provider_profiles;
DROP POLICY IF EXISTS provider_profiles_delete ON openfin8_eu.provider_profiles;