# FIP 0.2 Enforcement Candidate

FIP 0.2 is an Enforcement Candidate. It is a normative specification for an
enforcement-neutral operational authority protocol. It is not a published
standard. This directory is the specification. The reference evaluator,
coverage assessment, and target adapter live outside it.

This directory is the versioned 0.2 specification area. It does not modify FIP
0.1. The frozen 0.1 adapters, vocabulary, and 47 conformance vectors remain the
only executable definition of 0.1.

The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT,
MAY, and OPTIONAL are to be interpreted as in BCP 14 (RFC 2119 and RFC 8174).

## Status

Milestone M0 defines the specification and the design schemas. A conforming
document can be written and recognized by shape. The reference implementation
of evaluation, projection, coverage, and one pinned filesystem adapter is
outside this directory. The validated slice is described in
[filesystem-vertical-slice.md](filesystem-vertical-slice.md).

Target-neutral projection is specified in [enforcement-ir.md](enforcement-ir.md).
It copies an authorized operational slice into an Enforcement IR whose
compilation disposition is `NOT_COMPILED`. It does not apply a Capability
Manifest and it does not emit a target policy.

If this prose and a schema in `schema/` disagree, the disagreement is a
specification defect. Until it is corrected, a conforming implementation MUST
refuse the affected construct. It MUST NOT choose the reading that authorizes
more execution.

## Normative documents

| Document | Role |
| --- | --- |
| [architecture.md](architecture.md) | Purpose, layers, terminology, closed world |
| [primitives.md](primitives.md) | The 28 primitives |
| [relations.md](relations.md) | The 26 relationships |
| [documents.md](documents.md) | AuthorityPolicy, Exchange, semantic acts |
| [execution-binding.md](execution-binding.md) | Bindings, kinds, locators, operations, protocols |
| [enforcement-requirement.md](enforcement-requirement.md) | Requirements, composition, lifetime, approval, audit |
| [authority-objects.md](authority-objects.md) | Condition, Constraint, Scope, Validity, grants, delegation |
| [decisions.md](decisions.md) | Decision domains, fail-closed rules, initial reason codes |
| [enforcement-ir.md](enforcement-ir.md) | Enforcement IR contract and derivation |
| [adapters.md](adapters.md) | Capability Manifest, subset invariant, coverage, substrate |
| [audit-and-federation.md](audit-and-federation.md) | Audit correlation, FIP-side runtime observation, and cross-enterprise behavior |
| [compatibility.md](compatibility.md) | 0.1 preservation, lifting, version negotiation |
| [boundaries.md](boundaries.md) | OpenShell as a non-normative target; CAMEO outside FIP |
| [schema/README.md](schema/README.md) | Normative document shapes |
| [vocabulary/fip-0.2.jsonld](vocabulary/fip-0.2.jsonld) | Normative primitive and relationship enumeration |

## Non-normative illustrations

The JSON files under [examples/fip-0.2](../../../examples/fip-0.2/README.md) are
illustrations. They are not conformance vectors and they do not authorize a
deployment.

## What this specification does not contain

- The reference implementation. That code is not normative by being present
  in the repository.
- Vendor policy languages. A target policy is an adapter artifact, not a FIP
  document.
- CAMEO, Mission Blueprint, or automatic generation rules.
- A change to FIP 0.1 semantics.
