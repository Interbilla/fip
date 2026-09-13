import hashlib, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
class JavaScriptProvenanceTest(unittest.TestCase):
    def test_frozen_javascript_digest(self):
        actual = hashlib.sha256((ROOT / "reference/javascript/fip-reference.js").read_bytes()).hexdigest()
        self.assertEqual(actual, "7fc43338f5d586dad29c97635ac58a043922b674d76bf28efd0f42d15eb95947")

