"""The s3-tests deselect plugin must match exact test names, not prefixes (pytest's --deselect
drops `test_100_continue_error_retry` when asked to skip `test_100_continue`).

Run: python3 scripts/tests/deselect_test.py
"""

import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "s3-tests"))
import tidemark_deselect  # noqa: E402


def item(name, module="test_s3"):
    return SimpleNamespace(name=name, fspath=f"/x/s3tests/functional/{module}.py")


class Deselect(unittest.TestCase):
    def run_plugin(self, listing, names):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
            f.write(listing)
        os.environ["TIDEMARK_DESELECT_FILE"] = f.name
        dropped = []
        config = SimpleNamespace(hook=SimpleNamespace(pytest_deselected=lambda items: dropped.extend(items)))
        items = [item(n) for n in names]
        try:
            tidemark_deselect.pytest_collection_modifyitems(config, items)
        finally:
            os.unlink(f.name)
            del os.environ["TIDEMARK_DESELECT_FILE"]
        return [i.name for i in items], [i.name for i in dropped]

    def test_exact_match_not_prefix(self):
        kept, dropped = self.run_plugin(
            "test_s3::test_100_continue  ACL grant\n",
            ["test_100_continue", "test_100_continue_error_retry"],
        )
        self.assertEqual(dropped, ["test_100_continue"])
        self.assertEqual(kept, ["test_100_continue_error_retry"])

    def test_comments_blank_lines_and_other_modules(self):
        kept, dropped = self.run_plugin(
            "# header\n\ntest_s3::test_a # why\ntest_iam::test_b\n",
            ["test_a", "test_b", "test_c"],
        )
        self.assertEqual(dropped, ["test_a"])
        self.assertEqual(kept, ["test_b", "test_c"])

    def test_committed_list_parses(self):
        listing = Path(__file__).resolve().parents[1] / "s3-tests" / "acl-grants.txt"
        os.environ["TIDEMARK_DESELECT_FILE"] = str(listing)
        try:
            names = tidemark_deselect._names()
        finally:
            del os.environ["TIDEMARK_DESELECT_FILE"]
        self.assertTrue(names)
        self.assertTrue(all("::test_" in n for n in names), names)


if __name__ == "__main__":
    unittest.main(verbosity=1)
