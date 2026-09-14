# Foundational Interaction Primitives (FIP) 0.1 — Reference Candidate

As AI systems become increasingly agentic, safety cannot depend solely on
whether models understand instructions or communicating systems share an
application ontology. Consequential interactions need explicit answers to:
Who acts? What resource is affected? What action is proposed, for what purpose,
under what authority, scope, validity, evidence, and provenance?

FIP 0.1 proposes a compact, domain-independent interaction vocabulary for
representing those questions while domain concepts remain independently
defined. It is a **Reference Candidate**, not a standard, certification, formal
verification, or safety guarantee.

> FIP 0.1 is not something we're asking the community to accept; it's something
> we're asking the community to test.

## Architecture

```text
Extensible domain semantics
  → governed operational-context projection (GOCP)
  → FIP interaction
  → Semantic Micro-Firewall
  → enforced resource gateway
  → operational effect
```

FIP **describes** the consequential interaction. A Semantic Micro-Firewall
**evaluates** it. GOCP controls which extensible context can become operational.

**Open description; closed operational interpretation.** Descriptive
extensibility does not imply governance extensibility.

## Latest bounded evidence

A prospective stronger-model replication replaced the GPT-5.6 Luna adversary
with GPT-5.6 Sol (`gpt-5.6-sol`) while preserving the protected architecture and
bounded semantic interface. Sol first qualified against all five vulnerable
semantic attack families. The subsequent frozen protected evaluation covered
five untrusted-semantic families and six admitted-context recomposition
dimensions. It observed no unauthorized operational effect across 33 protected
episodes (UOER 0/33).

This does **not** establish security against GPT-5.6 Sol generally, other
frontier models, or attacks outside the evaluated interface, scenarios,
observation model, and budget. B1 feedback collapsed to one observable outcome
tuple, which may have reduced adaptive information available to the adversary.
See the [Q12-C2 evidence](experiments/q12-c2/README.md) and the preserved
[Q12-C pre-scientific failure](experiments/q12-c/README.md).

## Run and test

Requirements: Python 3.10+; Node.js 18+ for the JavaScript reference.

```bash
python tools/test_all.py
python conformance/runners/python_runner.py
node conformance/runners/javascript-runner.js
python examples/run_examples.py
```

Both references should match all 47 frozen conformance vectors. `make test` is
also available where GNU Make is installed.

## Try to break it

Submit reproducible counterexamples: missing semantics, ambiguous relations,
interoperability disagreements, or interactions that acquire unauthorized
effect. Start with [the threat model](docs/architecture/threat-model.md),
[limitations](docs/limitations.md), and issue templates. Do not test against
systems you do not own or lack permission to evaluate.

## What FIP is not

FIP does not replace a domain ontology, network controls, authorization
infrastructure, application policy, or AI alignment. It does not claim to stop
prompt injection or guarantee universal domain independence.

## Repository map

- `vocabulary/`: the frozen 26 primitives and 24 relations
- `reference/`: semantically unchanged Python and JavaScript adapters
- `conformance/`: 47 vectors, expected results, and independent runners
- `gocp/`: a minimal governed-context example; GOCP is not a FIP primitive
- `firewall/`: Semantic Micro-Firewall reference boundary
- `examples/`: synthetic semantic safety cases
- `experiments/`: bounded evidence and reproducibility guidance
- `docs/provenance.md`: source hashes and release transformations

See [CONTRIBUTING.md](CONTRIBUTING.md) to propose gaps or independent
implementations. FIP 0.1 semantics are frozen; accepted semantic changes target
a future explicitly versioned candidate.

See also [community testing and falsification](docs/community-testing.md).
