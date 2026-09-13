# Threat model

The evaluated attacker may inject natural-language-derived assertions,
classifications, relations, authority/delegation/credential/evidence/provenance
claims, memory, precedent, replay, cross-agent messages, and unknown extensions.
The security invariant is that interpretability alone cannot grant operational
authority. Effects must traverse projection, FIP evaluation, and the gateway.

Out of scope: compromised trusted policy stores, stolen valid credentials,
implementation memory corruption, network compromise, and unmodeled production
integration paths.

