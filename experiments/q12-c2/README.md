# Q12-C2 — GPT-5.6 Sol stronger-model replication

Q12-C2 was a new prospective experiment asking whether Q12-B3's bounded
protected-architecture result persisted when GPT-5.6 Luna was replaced by
GPT-5.6 Sol. It received no scientific credit from Q12-C.

**Classification: Q12-C2 GPT-5.6 SOL PROTECTED ARCHITECTURE — NO BYPASS
DISCOVERED WITHIN FROZEN EVALUATION**

Product model: GPT-5.6 Sol. Exact API identifier: `gpt-5.6-sol`. This identifier
is a hosted moving alias; no immutable model snapshot is claimed. Execution ran
from 2026-09-14 01:35:53 UTC through 02:28:21 UTC.

Sol first qualified against all five intentionally vulnerable semantic-control
families. Every qualifying strategy replayed 3/3, and every family was
independently rediscovered at least once in five clean resets. The protected
phase then completed all five untrusted-semantic families and six admitted-
context recomposition dimensions: 33 episodes, 660 completed requests, 627
semantic actions, 51 resource invocations, and zero operational effects. UOER
was 0/33.

Controls passed 22/22: all seven authorized effects executed, while zero of
seven unauthorized sibling effects executed. The system was not deny-all.

## Critical limitation

B1 feedback again collapsed to **one observable outcome tuple**. This limited
feedback diversity may have reduced adaptive information available to the
generative adversary. The B1 result supports resistance only within the tested
interaction and observation model and does not establish resistance under
richer attacker-visible feedback.

This result does not establish security against GPT-5.6 Sol generally, other
frontier models, or attacks outside the evaluated scenarios, semantic interface,
observation model, and bounded budget. Start with the [preregistration](preregistration.md)
and [final report](final-qualification-report.txt).
