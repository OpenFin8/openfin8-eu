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

The **XS2A consent + authorisation model is implemented** (OBARCH-7,
backlog EU-1/EU-2): the four-state consent machine (`received` →
`valid`/`rejected`/`expired`, `revoked` terminal) over the kernel's
`awaiting_authorization` state, the authorisation sub-resources (each
SCA ceremony its own object, `src/consent.rs`), the pre-step
(`POST /v1/consents/{id}/authorisations` with the SCA-approach
selection), and the schema `openfin8_eu` (consents, authorisations,
recipient registry, signing baskets) with the served-approach honest
configuration (`OPENFIN8_EU_SCA_APPROACHES`; `redirect` mandatory and
always served). The AIS/PIS/PIIS resource surfaces, the per-approach
Flow ceremonies, the eIDAS/DCR trust path, and the payments proxy
lanes land next (EU-3..EU-6).

- [Architecture (DDD)](https://github.com/OpenFin8/openfin8-eu/blob/main/DESIGN.md)
- [Business (BRD)](https://github.com/OpenFin8/openfin8-eu/blob/main/BUSINESS.md)
- [Spec references](https://github.com/OpenFin8/openfin8-eu/blob/main/specs/README.md)

---

**Architecture & Design:** openfin8:eu and its underlying concepts were
designed by [Hamid Jahanzad](https://www.linkedin.com/in/hamidjahanzad/).
