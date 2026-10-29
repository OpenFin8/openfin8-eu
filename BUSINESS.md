# OpenFin8:EU - Business Requirements & Functionality

> Status: **IN IMPLEMENTATION** (OBARCH-7). This BRD records the business
> scope the European adapter will deliver; section 9 lists the
> implementation acceptance criteria - the consent + authorisation
> model (bullet 2) has LANDED (backlog EU-2); the service is otherwise
> a skeleton (bullet 1 - current state).
>
> Audience: product owners, business analysts. For architecture read
> `README.md`; for wire-level detail read `DESIGN.md`.

## 1. Business Purpose

OpenFin8:EU is **European open finance**: the Berlin Group
**openFinance API Framework** (the NextGenPSD2 successor - the
standard's own name moved to open finance), serving AISPs, PISPs,
and PIISs over the XS2A wire. It will deliver:

- **PSD2-compliant account access + payment initiation** - the
  mandated EU surface: AIS, PIS, and PIIS with the consent-
  authorization pre-step.
- **All three SCA approaches** - redirect (mandatory), decoupled,
  and embedded - so an institution serves the interaction modes its
  PSD2 authorisation permits, over one kernel.
- **eIDAS-grade security** - QWAC (TLS) + QSEALC (signing)
  certificates, bank-by-bank DCR (no central directory - the EU
  trust model).
- **A PSD3/FDA-absorbable boundary** - the adapter is the seam
  where the Financial Data Access act lands; the kernel keeps the
  consent machinery stable across the transition.

## 2. Business Scope (What the Service Will Provide)

| # | Capability area | What the business gets |
|---|---|---|
| 1 | AIS | Account information: accounts, balances, transactions, card accounts - behind AIS consents |
| 2 | PIS | Payment initiation across the ISO payment products (SEPA, instant, cross-border, bulk) + status + cancellation |
| 3 | PIIS | Confirmation of funds (consent + check) |
| 4 | Consent API | The consent lifecycle + authorisation sub-resources + the pre-step |
| 5 | Signing baskets | Batch authorization of consents + payments in one PSU ceremony |
| 6 | Extended services | Mandates, RTP (request-to-pay), push AIS, discovery, documents |
| 7 | Admin console | The kernel pages under the EU identity |
| 8 | Events | Family `openfin8:eu:*` |
| 9 | Health | Fleet supervision |

**Not owned**: the implementation (openfin8-core), the data plane
(bank8:Ledger), execution (bank8:Payments), ceremony hosting
(Sentin8:Auth), other markets' surfaces (profile isolation).

## 3. Business Capabilities

### 3.1 The SCA approach set

One adapter, three interaction modes: redirect (PSU to the ASPSP's
SCA page), decoupled (SCA pushed to the PSU's device; the TPP
polls), embedded (challenge data through the TPP's frontend, where
the RTS exemptions permit). The served-approach list is honest
per-environment configuration.

### 3.2 The consent-authorization pre-step

XS2A consents carry explicit authorisation sub-resources - each SCA
ceremony is its own object, tracked separately from the consent
grant. The kernel's `awaiting_authorization` + intent payload
express it; Flow drives the per-approach steps.

### 3.3 The domestic-variant question (deferred)

The EU is not one wire in practice (STET/FR, PolishAPI/PL, Slovak
BA). The Berlin Group openFinance framework is the served default;
variants are customer-specific follow-ons on the UK-over-CA pattern
if a market demands them.

## 4. Business Events (Outbound)

Family `openfin8:eu:*`: consent + authorisation lifecycles, payment
lifecycles, basket events.

## 5. Business Rules & Invariants (as designed)

- Every kernel invariant holds.
- Payment initiation verifies the QSEALC signature; SCA success is
  never conflated with consent grant (separate state machines); the
  served SCA approach list matches the institution's PSD2
  authorisation.

## 6. Target-User Roles & Use Cases

| Role | Use case |
|---|---|
| EU institution (ASPSP) | Enable `openfin8:eu`; serve PSD2 AIS/PIS/PIIS with the permitted SCA approaches |
| TPP (AISP/PISP/PIISP) | DCR per ASPSP, run PSU journeys, consume account data / initiate payments |
| Bank customer (PSU) | Authorizes via the institution's chosen SCA mode |
| National competent authority | PSD2 compliance evidence from the audited traffic |

## 7. KPIs / Success Criteria

- **Conformance**: the Berlin Group openFinance test suites pass.
- **SCA coverage**: every served approach green against the Auth
  ceremony on a scratch org.
- **PSD3-absorbability**: the adapter boundary survives the FDA
  transition without a kernel rewrite.

## 8. Dependencies & Reliance on Other Services

The kernel + platform set, plus: **eIDAS QWAC/QSEALC certificates**
(secrets-referenced per environment) and **bank-by-bank DCR**
(each ASPSP's AS - no central directory integration).

## 9. Acceptance Criteria (the implementation's definition of done)

- The skeleton builds + the publication guard passes (vendored with
  CC BY attribution) - **current state**.
- The XS2A consent + authorisation model over the kernel lands (the
  four-state consent machine + the pre-step) - **LANDED (EU-2)**.
- All three SCA approach ceremonies green against Auth (redirect
  mandatory; decoupled + embedded conditional) - **LANDED (EU-3)**:
  the three ceremony routes over the per-approach machine + the Flow
  step-handler profile; the Auth ceremony drive rides the recipient-app
  story (the browser-driven PSU page).
- The signing-basket batch flow + the ISO payment products through
  Payments - **LANDED (EU-5)**: the batch authorization + the four ISO
  products through the Payments public API, behind the fail-closed
  QSEALC verification (EU invariant 1).
- The e2e journey gains the redirect-SCA AIS + PIS flows - **LANDED
  (EU-8)**: `openfin8_eu_xs2a_journey.spec.ts` (the discovery contract,
  the redirect ceremony to VALID, the failed-challenge isolation, the
  QSEALC fail-closed verdict, the honest 501s).
- AIS + PIIS behind the consent chokepoint - **LANDED (EU-6)**; the
  Extended Services answer honestly until their resource families ship
  (**EU-7**: discovery served; mandates/RTP/push-AIS/documents 501,
  never stubbed data); the eIDAS trust path is secret-referenced +
  bank-by-bank DCR-shaped (**EU-4**; the resolved-key verification is
  the production material story); the published spec + site unit +
  drift guard landed (**EU-9**).
- The signing-basket batch flow + the ISO payment products through
  Payments.
- The e2e journey gains the redirect-SCA AIS + PIS flows.

## 10. Open Business Questions

- Ship openFinance V2 conformance now and absorb PSD3/FDA as a
  follow-on wire family, or hold EU until the final act?
  (Recommendation: ship V2 - the live standard; PSD3 timing is
  uncertain.)
- Domestic variants (STET, PolishAPI, Slovak): served variants on
  this adapter or customer-specific follow-ons?
- Embedded SCA in v1, or redirect-only first? (Conservative:
  redirect-only v1.)

---

**Architecture & Design:** openfin8:eu and its underlying concepts
were designed by [Hamid Jahanzad](https://www.linkedin.com/in/hamidjahanzad/).