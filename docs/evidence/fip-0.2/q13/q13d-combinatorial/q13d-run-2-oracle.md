# q13d-run-2 oracle note

`q13d-run-2` is preserved as the generator wrote it. This note is outside that directory.

The stop at `q13d-seed-0001-0167-resource=missing` is an oracle defect. That case is a valid Delegation. Delegation does not require a resource. The exchange named no substitute resource, `canDelegate` was true, and the evaluator authorized the delegated action. The oracle had treated every missing resource as a denial, including acts whose required fields do not include a resource.

The next run applies the missing-resource and missing-purpose checks only to acts that require those fields.
