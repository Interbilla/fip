# Design schemas

These schemas are normative for document shape. Evaluation behavior is
normative in the prose of this specification. A document that fails its schema
is not a conforming document.

| Schema | Document |
| --- | --- |
| [common.schema.json](common.schema.json) | Shared definitions used by the other schemas |
| [authority-policy.schema.json](authority-policy.schema.json) | AuthorityPolicy |
| [exchange.schema.json](exchange.schema.json) | Exchange |
| [enforcement-ir.schema.json](enforcement-ir.schema.json) | Enforcement IR, a compiler output |
| [capability-manifest.schema.json](capability-manifest.schema.json) | Adapter Capability Manifest |
| [compilation-profile.schema.json](compilation-profile.schema.json) | FIP compilation profile. Accepts execution substrate and may declare a target executable restriction. Not a target policy and not a FIP grant. |
| [coverage-assessment.schema.json](coverage-assessment.schema.json) | Coverage assessment. Not a target policy. |
| [audit-correlation.schema.json](audit-correlation.schema.json) | Audit correlation record. This is the only record that can satisfy `audit` `correlated`. |
| [runtime-observation.schema.json](runtime-observation.schema.json) | FIP-side runtime observation. Not an audit-correlation record. |

Schemas use JSON Schema draft 2020-12. References to shared definitions use
the `urn:fip:0.2:common` identifier. The instance encoding for M0 is JSON.
This specification does not define a second encoding.

The schemas do not decide authority. They reject undeclared fields, including
vendor policy fields and secret-bearing properties that are not in the model.
Cross-reference integrity, prohibition dominance, and compilation are
evaluator and compiler duties specified in the prose. They are not fully
expressed here.

`failClosed` is not a property of EnforcementRequirement. `custom` values are
reserved and are not conforming operational documents in M0, as stated in
[architecture.md](../architecture.md).
