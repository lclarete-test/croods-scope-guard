import tempfile
import unittest
from pathlib import Path

from croods_scope_guard.audit import audit
from croods_scope_guard.report import markdown, save


class AuditTests(unittest.TestCase):
    def test_flags_unfiltered_fallback_with_source_line(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            path = root / "lib/croods/policy/scope.rb"
            path.parent.mkdir(parents=True)
            path.write_text("def tenant_scope(scope)\n  path = reflection_path(scope, :organization)\n  return scope if path.empty?\nend\n", encoding="utf-8")
            result = audit(root)
            self.assertEqual([f["id"] for f in result["findings"]], ["CSG001"])
            self.assertEqual(result["findings"][0]["location"], "lib/croods/policy/scope.rb:3")
            self.assertFalse(result["runtime_executed"])
            self.assertIn("No Rails requests were executed", markdown(result))
            outputs = save(result, root / "out")
            self.assertEqual([p.suffix for p in outputs], [".md", ".html", ".json"])

    def test_does_not_label_a_missing_fallback_as_safe(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "lib/croods/policy/scope.rb"
            path.parent.mkdir(parents=True)
            path.write_text("def tenant_scope(scope)\n  raise 'Unscoped' if path.empty?\nend\n", encoding="utf-8")
            result = audit(folder)
            self.assertEqual(result["findings"], [])
            self.assertIn("does not prove", markdown(result))

    def test_invalid_repository_is_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaisesRegex(ValueError, "Not a Croods repository"):
                audit(folder)


if __name__ == "__main__":
    unittest.main()
