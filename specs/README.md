# OpenFin8:EU - Upstream Specification References

**The Berlin Group openFinance OpenAPI files may be vendored - with attribution.**

The Berlin Group publishes the openFinance OpenAPI files under
**Creative Commons Attribution 4.0 (CC BY 4.0)** - the licence
notice explicitly permits copying and adaptation with attribution
(the Implementation Guidelines documents are CC BY-ND; the OpenAPI
YAMLs are the adaptable form). This repository MAY include the
openFinance resource paths with the attribution preserved - the CI
drift guard enforces it.

Optional local reference copies, gitignored:

```
specs/bg/{version}/        # your local copy of the BG_oFA_*_openapi.yaml files
```

Operators download from
<https://gitlab.com/the-berlin-group/openfinance> (the OpenAPI
repository; the normative reference remains the Implementation
Guidelines). Nothing in this service reads them at runtime - the
served surface is configured via `OPENFIN8_EU_VERSION`.

Note: the EU has domestic variants (STET/FR, PolishAPI/PL, Slovak BA
API); the Berlin Group openFinance framework is the served default.

Contrast: the FDX (US/CA) adapters must NEVER publish the licensed
FDX specification - see their repositories.
