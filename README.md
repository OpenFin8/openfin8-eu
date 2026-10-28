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

In design (OBARCH-7): DESIGN.md covers the XS2A wire, the consent +
authorisation model, the PSD3/FDA absorbability boundary, and the
domestic-variant question.

- [Architecture (DDD)](https://github.com/OpenFin8/openfin8-eu/blob/main/DESIGN.md)
- [Business (BRD)](https://github.com/OpenFin8/openfin8-eu/blob/main/BUSINESS.md)
- [Spec references](https://github.com/OpenFin8/openfin8-eu/blob/main/specs/README.md)

---

**Architecture & Design:** openfin8:eu and its underlying concepts were
designed by [Hamid Jahanzad](https://www.linkedin.com/in/hamidjahanzad/).
