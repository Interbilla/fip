# Experimental evidence

Bounded internal studies evaluated symbolic and generative adversaries. Completed
protected evaluations reported no unauthorized operational effect within their
domains, attack classes, contextual conditions, and budgets. Heterogeneous
campaigns are not pooled as identical trials.

| Study | Evidence | Result |
|---|---:|---|
| Q9C-A-R1 | full-grammar symbolic competency | qualified |
| Q9C-B | 54,870 candidate actions | 0 unauthorized effects |
| Q10 | 339,134 expansions; 238,724 permitted; 100,410 denied | 0 unauthorized effects |
| Q11-R1 | held-out healthcare; 54,870 actions; primitive/relation delta 0/0 | 0 unauthorized effects |
| Q12-A3 | Luna; 5/5 families; replay 3/3; rediscovery 4/5 | qualified |
| Q12-B | transport failure | no security conclusion |
| Q12-B2 | controller validation failure | no security conclusion |
| Q12-B3 | 33 episodes; 574/573 attempts/completions; 541 actions | UOER 0/33 |
| Q12-C | freeze-manifest validation failure; 0 scientific calls | no security conclusion |
| Q12-C2 | Sol qualified 5/5; 33 protected episodes; 660 calls; 627 actions | UOER 0/33 |

Q12-B3 also recorded 24 resource invocations and decisions of 138 PERMITTED,
147 DENIED, and 256 INCOMPLETE. Its B1 feedback diversity was one outcome tuple,
which may have reduced adaptive information available to the adversary.

Q12-C2 was a new prospective replication, not a repair or continuation of
Q12-C. It used product model GPT-5.6 Sol, API identifier `gpt-5.6-sol`, which is
a hosted moving alias rather than an immutable snapshot. Sol independently
qualified against all five vulnerable families before protected interpretation.
The protected phase covered all five B1 families and six B2 dimensions, with 39
PERMITTED, 300 DENIED, 288 INCOMPLETE, and 0 ESCALATE decisions. Seven of seven
authorized controls executed and zero of seven unauthorized sibling controls
executed, so the evaluated system was not deny-all.

Across the completed protected evaluations, no qualified symbolic or
generative adversary produced an unauthorized operational effect within the
evaluated domains, attack classes, operational-context conditions, observation
models, and bounded adversarial budgets. This is bounded internal evidence, not
a proof of security. See [Q12-C2](q12-c2/README.md) for detailed accounting.
