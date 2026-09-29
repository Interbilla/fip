# FIP 0.1 compatibility and version negotiation

## Preservation

FIP 0.1 remains frozen. This specification does not change:

- `reference/python/fip_reference/core.py`
- `reference/javascript/fip-reference.js`
- `vocabulary/fip-0.1.jsonld`
- `vocabulary/fip-0.1.schema.json`
- `conformance/vectors/`
- `conformance/expected-results/`
- the 0.1 prose under `docs/specification/` that states the 0.1 freeze

The only executable definition of a 0.1 exchange is the frozen adapters and
the 47 conformance vectors. A 0.2 implementation MUST NOT claim to execute
0.1 by editing those artifacts.

## What stays recognizable

The 26 original primitive names, the 24 original relationship names, the eight
semantic acts, the five validity states, the three scope dimensions, the
separation of evidence, provenance, and credential, explicit delegation, and
the rule that extensions and free text do not create authority.

## What 0.2 changes on purpose

| 0.1 behavior | 0.2 behavior |
| --- | --- |
| Firewall value `PERMITTED` means required structured fields were present. | `AUTHORIZED` means the normative structure holds. It is not a runtime allow. There is no `PERMITTED` value. |
| `ESCALATE` | `REVIEW`, or `INCOMPLETE` when the cause is missing structure. Never `AUTHORIZED`. |
| `policy` identifier presence can complete a permit. | An identifier-only policy is semantic-only. Operational policy contains requirements. |
| Condition and Constraint are names without fields. | They have types and are evaluated. Unevaluable conditions are `INCOMPLETE`. |
| Normative force is a summary string. | `permits`, `prohibits`, and `obligates` are edges and MUST agree with the summary when both are present. |
| One exchange document. | AuthorityPolicy and Exchange. |
| No execution bindings. | Bindings are required before any deployable compilation. |
| An obligated instruction can be `PERMITTED` because it is structurally complete. | An obligation does not grant execution authority. |

## Lifting

A lifter MAY wrap a 0.1 exchange as a 0.2 Exchange. The lifted document MUST
set `fipVersion` to `0.2`, `document` to `Exchange`, `mode` to `semantic-only`,
and `fipCompat` to `0.1`. It MUST copy the semantic fields it understands and
MUST set `executionBindings` and `enforcementRequirements` to empty arrays
when it includes those properties.

The lifter MUST NOT invent locators from `resource.id` or from an action
string. The lifter MUST NOT set a compilation disposition in the document.
The compilation disposition of a lifted document, when a compiler is asked, is
`NOT_COMPILED`. A compiler MUST refuse to emit a deployable artifact from it.

A 0.1 `PERMITTED` maps to a semantic outcome that can be `AUTHORIZED` only in
semantic-only mode, with compilation `NOT_COMPILED`. It does not map to
`FULL`. A 0.1 `DENIED` remains `DENIED`. A 0.1 `INCOMPLETE` remains
`INCOMPLETE`. A 0.1 `ESCALATE` maps to `REVIEW`, except when the 0.1 code is
`incomplete_structured_fields`, which stays `INCOMPLETE`.

A 0.1 obligation that was permitted by structure lifts as semantic-only. The
lifter MUST NOT attach an invented audit obligation.

## Version negotiation

Every 0.2 document carries `fipVersion`.

| Presented version | Required behavior |
| --- | --- |
| Absent | Reject the document. Produce no allow. Code `unknown_fip_version`. |
| `0.1` | Accept only as lifter input. Do not compile. Do not modify the 0.1 bytes. |
| `0.2` | Apply this specification. |
| Any other value | Reject the document. Produce no allow. Code `unknown_fip_version`. |

An adapter MUST refuse an IR whose `fipVersion` is not `0.2`.

Unknown binding kinds, operations, protocol families, and requirement effects
fail closed. They are not interpreted as the nearest supported value.
