# Community testing and falsification

Useful contributions try to disprove or delimit the candidate:

- propose a missing primitive or relation with a reproducible operational gap;
- report ambiguity or cross-implementation disagreement;
- implement FIP independently and run all vectors;
- submit a semantic bypass showing an unauthorized executed effect;
- challenge whether a GOCP mapping admits too much or starves useful context;
- reproduce adversarial methodology with frozen budgets and independent oracles.

Distinguish domain vocabulary from interaction vocabulary. A concept should
remain domain-specific unless consequential interactions cannot be represented
without adding it to FIP. Never test third-party systems without authorization.

