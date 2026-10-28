# openfin8-eu - Detailed Design Document

> Status: **PROPOSED** - the European open-finance adapter (OBARCH-7).
> The Berlin Group **openFinance API Framework** (the NextGenPSD2
> successor - the standard's own name moved to open finance), V2
> line (XS2A V2.4.x, Consent API 2.2.x). Depends on:
> `openfin8-core` (OBARCH-1). Read `openfin8-uk/DESIGN.md` for the
> sibling design; this document defines the EU deltas. **Note**: the
> heaviest adapter of the set - three SCA interaction modes, no
> central directory, and PSD3/FDA in flight.

## 1. Scope & Context

**What this service is.** The European open-finance adapter
(`service_type: openfin8:eu`, binary `openfin8-eu`): the XS2A
Account Servicing Payment Service Provider surface - AIS (account
information), PIS (payment initiation), PIIS (confirmation of
funds) - over the Berlin Group openFinance V2 wire, plus the
extended services (consent, signing baskets, mandates, RTP, push
AIS, discovery, documents).

**The wire family: XS2A** - its own ceremony family (not FAPI-JWS,
not CDR). Three defining properties:

1. **SCA approaches** - redirect, decoupled, and embedded: three
   interaction modes between the PSU, the ASPSP, and the TPP, each
   with its own contract (the redirect is mandatory; the others are
   conditional per the RTS).
2. **The consent-authorization pre-step** - unlike UK's intent
   staging, XS2A consents carry explicit `*Authorisation` sub-
   resources that each require their own SCA ceremony.
3. **No central directory** - recipient onboarding is bank-by-bank
   DCR against each ASPSP's AS; eIDAS QWAC (TLS) and QSEALC
   (signature) certificates are the trust anchors.

## 2. The XS2A Wire (as designed, per the verified research)

| Family | Resources | Notes |
|---|---|---|
| **AIS** | accounts, balances, transactions, card accounts; the consent resource + authorisations | `GET /v1/accounts`, `/balances`, `/transactions` behind an AIS consent |
| **PIS** | payment initiation (SEPA credit transfer, instant, cross-border, bulk), payment status, cancellation | `POST /v1/payments/{payment-product}`; signing baskets batch them |
| **PIIS** | confirmation of funds | funds-confirmation consent + the check |
| **Consent API** | the consent lifecycle + authorisation sub-resources | Core's `awaiting_authorization` + the four-state XS2A consent model (`received`/`valid`/`rejected`/`expired`) |
| **Signing baskets** | batch authorization of multiple consents/payments in one PSU ceremony | Distinct EU concept; maps to Flow steps |
| **Extended** | mandates, RTP (request-to-pay), push AIS, discovery, documents | The V2 Extended Services suite |

**Envelope**: XS2A JSON (`{_links, ...}` HAL-style links,
`tppMessages`), the ISO 20022-derived payloads (payment products
are ISO pain/pacs message families).

## 3. Ceremony: SCA Approaches + eIDAS

1. **DCR bank-by-bank** - no directory; each ASPSP's AS registers
   the TPP (RFC 7591 with the eIDAS-asserted identity).
2. **eIDAS certificates** - QWAC for TLS client auth, QSEALC for
   signing; the ceremony ctx carries the references per environment.
3. **The SCA flows**:
   - *Redirect*: consent → `startAuthorisation` → redirect the PSU
     to the ASPSP's SCA page → callback → token.
   - *Decoupled*: the ASPSP pushes the SCA request to the PSU's
     device/app (the PSU authorizes out-of-band); the TPP polls
     authorisation status.
   - *Embedded*: SCA challenge data exchanged through the TPP's
     frontend (conditional - regulated per the RTS exemption rules).
   The platform's Flow engine drives the per-approach steps; the
   adapter declares which it serves (redirect mandatory).
4. **Pre-step authorization** - each authorisation sub-resource
   carries the SCA selection before the PSU ceremony begins.

**Consent lifecycle mapping** (core ↔ XS2A):
`awaiting_authorization` (received) → `active` (valid) →
`revoked`/`expired`. The authorisation sub-resources ride
`intent_payload`; core's state machine holds; the per-approach
ceremonies are adapter + Flow steps.

## 4. Money Movement

Payment initiation proxies to bank8:Payments: consent (PIS
authorisation) → payment submission (the ISO payment product) →
status. Signing baskets batch authorisations and map to Payments'
bulk/file pipelines.

## 5. Registration & Configuration

- `service-registration.json`: service type `openfin8:eu`; Shield
  gates `openfin8:eu:*`.
- Env: `OPENFIN8_EU_PORT`, `OPENFIN8_EU_DATABASE_URL`,
  `OPENFIN8_EU_BASE_URL`, `OPENFIN8_EU_VERSION` (the openFinance
  V2.x version), `OPENFIN8_EU_QWAC_CERT_REF`/`_KEY_REF`,
  `OPENFIN8_EU_QSEALC_CERT_REF`/`_KEY_REF`, the served SCA-approach
  list (`redirect` mandatory). Per-env overrides via
  `sys.services.config`.

## 6. Spec Publication (OBARCH-2)

**Vendored with attribution**: the Berlin Group OpenAPI files are
published under **CC BY 4.0** (the licence notice explicitly
permits copying and adaptation with attribution); the *documents*
are CC BY-ND. This adapter MAY carry the openFinance resource paths
from the OpenAPI files with the attribution preserved; the drift
guard asserts the attribution and the path prefixes.

## 7. Invariants (as designed)

- Every kernel invariant holds.
- **EU additions**: every payment initiation verifies the QSEALC
  signature; the authorisation state machine is per-approach and
  never conflates SCA success with consent grant; the served SCA
  approach list is honest (embedded is only served where the RTS
  exemption rules allow).

## 8. Open Questions

- **PSD3/FDA** (Financial Data Access, in flight) will reshape this
  surface - the adapter boundary must absorb the transition; do we
  ship V2 conformance now and treat PSD3 as a follow-on wire family,
  or hold EU until the final act? (Recommendation: ship V2 - the
  Berlin Group openFinance framework is the live standard and
  PSD3/FDA timing is uncertain.)
- Domestic variants (STET for FR, PolishAPI for PL, Slovak BA API):
  does the EU adapter grow variant profiles (like CA over the FDX
  wire), or do we serve the Berlin Group default and treat variants
  as customer-specific follow-ons?
- Embedded SCA: in or out of v1? (Regulated but conditional; the
  redirect-only v1 is the conservative start.)

---

**Architecture & Design:** openfin8:eu and its underlying concepts
were designed by [Hamid Jahanzad](https://www.linkedin.com/in/hamidjahanzad/).