# OpenFin8:EU - README

**European open finance (Berlin Group openFinance V2): AIS/PIS/PIIS
with SCA approaches, eIDAS certificates, consent authorisation
pre-steps, signing baskets.**

OpenFin8:EU is the European adapter over the openfin8-core kernel:
the XS2A surface - account information, payment initiation, and
confirmation of funds - over the Berlin Group openFinance framework
(the NextGenPSD2 successor). The ceremony is its own family:
bank-by-bank DCR (no central directory), eIDAS QWAC/QSEALC
certificates, and the three SCA approaches (redirect mandatory;
decoupled + embedded conditional per the RTS).

The **served XS2A surface**:

- the **consent + authorisation model** - the four-state consent
  machine over the kernel's `awaiting_authorization` state, the
  authorisation sub-resources (each SCA ceremony its own object), the
  pre-step with the honest SCA-approach selection (`src/consent.rs`);
- the **three SCA ceremonies** (`src/ceremony.rs`) - redirect (the
  start/callback pair), decoupled (the push + poll), embedded (the
  challenge/answer pair), all driving the same per-approach machine
  through the observation path (SCA success never conflated with the
  grant) + the Flow step-handler profile (the proxy-back lane);
- the **eIDAS trust path + bank-by-bank DCR** (`src/eidas.rs`) - the
  QWAC/QSEALC secret-reference configuration (never key material)
  and the fail-closed QSEALC enforcement every payment initiation
  verifies;
- **PIS + signing baskets** (`src/payments.rs`) - the ISO payment
  products through the Bank8:Payments public API (the OBVERT
  boundary), the QSEALC fail-closed gate, and the batch
  authorization;
- **AIS + PIIS** (`src/ais.rs`) - the accounts/balances/transactions
  reads + the funds-confirmation check behind the consent chokepoint
  (a revoked consent stops serving on the very next call);
- the **Extended Services** (`src/extended.rs`) - the honest discovery
  advertisement + the unsupported answers (never stubbed data) for
  the unserved resource families;
- the **e2e journey** (`openfin8-e2e`: `openfin8_eu_xs2a_journey.spec.ts`)
  - the redirect-SCA AIS ceremony to VALID, the failed-challenge
  isolation, the QSEALC fail-closed verdict, the discovery contract,
  and the honest 501s;
- the **published spec + site** - 28 ops under the CC BY 4.0
  attribution, the OAPEC drift guard both directions, and the
  `openfin8-eu` unit on openfin8.dev.

The schema is `openfin8_eu` (consents, authorisations, signing
baskets, the recipient registry, the provider catalog; FORCE-RLS
env-pinned). The deferred surfaces: the browser-driven PSU SCA page
(the recipient-app story), the real QSEALC material verification
(the resolved-key path over the fixture), and the extended resource
families.

- [Architecture (DDD)](https://github.com/OpenFin8/openfin8-eu/blob/main/DESIGN.md)
- [Business (BRD)](https://github.com/OpenFin8/openfin8-eu/blob/main/BUSINESS.md)
- [Spec references](https://github.com/OpenFin8/openfin8-eu/blob/main/specs/README.md)

---

**Architecture & Design:** openfin8:eu and its underlying concepts were
designed by [Hamid Jahanzad](https://www.linkedin.com/in/hamidjahanzad/).
