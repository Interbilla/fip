"""FIP 0.2 authority evaluation and target-neutral projection.

assess() decides authority. project() copies an AUTHORIZED operational slice
into an Enforcement IR and does not compile it. assess_coverage() compares
that IR with a Capability Manifest. It does not emit a target policy.
"""

from .authority import assess
from .coverage import assess_coverage
from .project import project

__all__ = ["assess", "assess_coverage", "project"]
