# Purpose and architecture

## Purpose

FIP 0.2 specifies how a governed AI-agent interaction states who is authorized
to do what, to which semantic resource, why, and under which authority, and
which execution controls are required before that authorization may be compiled
into a target enforcement system.

FIP is the semantic authority. A target runtime is an enforcement mechanism.
The specification is enforcement-neutral: a second target MUST be expressible
without adding that target's vocabulary to FIP.

## Layers

A conforming deployment has these roles. M0 specifies them. It does not
implement them.

1. **Admission (GOCP).** A versioned allow-list decides which domain fields,
   binding kinds, and extension namespaces may become operational. GOCP is
   architecture around FIP. It is not one of the 28 primitives. Unadmitted
   material remains descriptive. An agent MUST NOT change the active profile
   or its mapping rules during a run.
2. **Semantic authority.** Actor, identity, role, resource, action, purpose,
   authority, authorization, permission, prohibition, obligation, delegation,
   policy, evidence, provenance, validity, and scope. This layer is portable
   across enterprises.
3. **Execution binding.** Maps a semantic resource or action to runtime
   entities. Bindings are local. A receiving enterprise MAY replace locators.
4. **Enforcement requirements.** Security obligations: effect, constraints,
   lifetime, approval, and audit. These travel with the authority. They MUST
   NOT name a vendor control.
5. **Enforcement IR.** A target-neutral projection of an authorized evaluation.
   It is not an independent grant. Adapters consume a verified projection.
   They MUST NOT re-decide authority, and they MUST NOT treat an unverified
   or substituted IR as the decision. Derivation is specified in
   [enforcement-ir.md](enforcement-ir.md).
6. **Target adapter.** Publishes a Capability Manifest, compiles the IR, and
   reports coverage. The first reference target is identified in
   [boundaries.md](boundaries.md). Its vocabulary is not part of FIP.

```text
GOCP admission
      |
      v
AuthorityPolicy = semantic authority
                + execution bindings
                + enforcement requirements
      |
      v
Exchange -- Semantic Micro-Firewall --> authorityDecision
      |
      v
Enforcement IR + coverage --> compilationDisposition
      |
      +------------------+------------------+
      v                  v                  v
 reference target       OPA           Kubernetes
      |
      v
 runtimeDisposition (observed, not granted)
```

OPA and Kubernetes in the figure are possible later targets. They are not
specified by name anywhere in the core vocabulary.

## Document types

FIP 0.2 has two primary document types:

- **AuthorityPolicy**, the standing document an author maintains.
- **Exchange**, one proposed interaction evaluated against a policy.

Compiler outputs (Enforcement IR, coverage, audit correlation) are specified
contracts. They are not authoring documents and they are not primitives.

## Terminology

| Term | Meaning |
| --- | --- |
| Semantic resource | A Resource. It has no runtime path, host, port, model id, or device id. |
| Semantic action | An Action. It is not a filesystem or network verb. |
| Execution authorization | An observed runtime allow. It requires `AUTHORIZED`, satisfied preconditions, `FULL` compilation, and `ENFORCED_ALLOW`. `FULL` alone is not execution authorization. |
| Deployable artifact | A target policy a runtime may install. Only FULL compilation produces one. |
| Candidate output | Non-deployable diagnostic material that PARTIAL compilation MAY emit. |
| Target baseline (substrate) | A control the target applies around the execution context. Execution substrate is not a FIP grant. Operational authority the target adds is still compared with the grants. |
| FIP grant | An operation a permit requirement authorizes, after prohibitions are applied. |
| Fail-closed | Missing, unknown, or unenforceable material does not become permission or a deployable allow. This is a property of the specification, not a document field. |
| Closed world | An operational policy authorizes only the operations its undominated permit requirements name. |
| Semantic-only | A 0.2 document with no execution bindings. It can carry authority and MUST NOT compile to a deployable artifact. |
| Operational | A 0.2 document that states bindings and requirements and may be compiled. |

## Authority is not execution

`authorityDecision` `AUTHORIZED` means the semantic structure holds and no
applicable prohibition or failed validity rule denies it. It does NOT mean a
runtime may perform the action.

Execution is authorized only when all of the following are true:

- `authorityDecision` is `AUTHORIZED`.
- Every applicable obligation and approval precondition is satisfied.
- `compilationDisposition` is `FULL`.
- A runtime later reports `runtimeDisposition` `ENFORCED_ALLOW` for that
  compiled rule.

A runtime allow does not rewrite a FIP denial.

`compilationDisposition` `FULL` additionally requires the derivation check in
[enforcement-ir.md](enforcement-ir.md): the security-relevant content of the
IR equals a fresh projection of the current semantic evaluation. An external
technical-boundary proof of a target policy does not replace that check. The
deployment order is semantic evaluation, projection, derivation verification,
coverage, adapter compilation, an optional target technical-boundary proof,
effective target-policy verification, then deployment. Product names for
targets and provers are not FIP vocabulary.

## Closed world

In an operational policy, an operation that is not named by an undominated
permit requirement is not authorized. Unmentioned paths, hosts, credentials,
models, devices, and channels are not authorized.

Absence of a prohibition is not permission. Absence of a permission is not a
prohibition. A semantic-only document authorizes no execution, including when
its normative state is `allowed`.

## Admission of extensions

Extension objects MAY describe domain facts. An extension MUST NOT be treated
as authority, authorization, permission, prohibition, obligation, delegation,
provenance, policy, or validity. A claim that attempts those roles makes the
document fail closed: a conforming evaluator MUST return `DENIED` for the
exchange and MUST NOT compile a permit from that claim.

The `custom` binding kind, operation, protocol family, condition type, and
constraint type are reserved. M0 defines no GOCP profile that admits a custom
namespace. A document that uses `custom` is therefore not a conforming
operational document. A conforming implementation MUST NOT treat it as
authorized execution.
