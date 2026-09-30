# q13d-run-3 oracle note

`q13d-run-3` is preserved as the generator wrote it. This note is outside that directory.

The stop at `q13d-seed-0003-0013-surface=approval-sequence=E-absent` is a generator defect. The case specified no approval, but the builder attached the current approval decision whenever the surface was the approval policy. The evaluator then authorized that current approval and emitted an operational IR. That is the specified behavior for a current approval, not acceptance of an absent one.

The next run attaches an approval decision only when the case asks for one.
