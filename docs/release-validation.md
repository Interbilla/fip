# Release validation

Local candidate validation:

- Python conformance: 47/47 PASS
- JavaScript conformance: 47/47 PASS
- unit tests: 6/6 PASS
- Draft 2020-12 schema validation: PASS (`jsonschema` 4.25.1)
- synthetic examples: 8/8 PASS
- GOCP projection example: PASS
- internal links: PASS
- Python wheel build: PASS
- copied adapter/vector equivalence: PASS (96/96 source-derived files)
- sensitive-data scan: 0 findings
- proprietary-material review: no application code or customer data found;
  explicit no-import/exclusion references to CAMEO/BILLA were reviewed
- license-term review: Apache License text retained byte-for-byte; NOTICE uses
  the approved `Copyright 2026 Interbilla LLC` attribution
- claim-discipline and hostile public-release review: PASS with limitations retained

GNU Make was unavailable on the validation host; the equivalent primary command
`python tools/test_all.py` passed. CI also uses this command.

Publication metadata was approved as: Interbilla LLC; Edward T. Chow;
`info@interbilla.com`; Git author `Edward T. Chow <echow@interbilla.com>`.
The repository was subsequently published without moving the immutable
`fip-v0.1-rc` tag. The release-local namespace remains intentionally
unregistered and is documented as a limitation.
