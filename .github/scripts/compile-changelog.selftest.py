#!/usr/bin/env python3
"""Regression tests for compile-changelog.py."""

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parent / "compile-changelog.py"
BASE = "# Changelog\n\n## [Unreleased]\n\n### Fixed\n- old\n\n## [1.0]\n- x\n"


def run(cwd, *args):
    return subprocess.run(
        [sys.executable, "-I", str(SCRIPT), *args],
        cwd=cwd, capture_output=True, text=True,
    )


class CompileChangelogTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.outer = Path(self._tmp.name).resolve()
        self.root = self.outer / "repo"
        (self.root / "changelog.d").mkdir(parents=True)
        self.write_changelog(BASE)

    def write_changelog(self, text):
        (self.root / "CHANGELOG.md").write_bytes(text.encode("utf-8"))

    def frag(self, name, data="entry"):
        (self.root / "changelog.d" / name).write_bytes(
            data if isinstance(data, bytes) else data.encode("utf-8"))

    def changelog(self):
        return (self.root / "CHANGELOG.md").read_bytes().decode("utf-8")

    def test_merge_into_existing_and_new_section(self):
        self.frag("1.fixed.md", "new fix")
        self.frag("2.added.md", "new feature")
        r = run(self.root)
        self.assertEqual(r.returncode, 0, r.stderr)
        out = self.changelog()
        self.assertIn("### Fixed\n- new fix\n- old\n", out)
        self.assertIn("### Added\n- new feature\n\n## [1.0]", out)
        self.assertFalse((self.root / "changelog.d" / "1.fixed.md").exists())

    def test_crlf_preserved(self):
        self.write_changelog(BASE.replace("\n", "\r\n"))
        self.frag("1.fixed.md", "crlf fix")
        self.assertEqual(run(self.root).returncode, 0)
        out = self.changelog()
        self.assertIn("- crlf fix\r\n- old\r\n", out)
        self.assertNotIn("\n", out.replace("\r\n", ""))

    def test_dry_run_changes_nothing(self):
        self.frag("1.fixed.md")
        r = run(self.root, "--dry-run")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.changelog(), BASE)
        self.assertTrue((self.root / "changelog.d" / "1.fixed.md").exists())

    def test_root_outside_cwd_rejected(self):
        for arg in ("..", str(self.outer), "../..", "sub/../.."):
            with self.subTest(root=arg):
                r = run(self.root, "--root", arg)
                self.assertEqual(r.returncode, 2, r.stderr)
                self.assertIn("--root", r.stderr)

    def test_symlinked_root_escape_rejected(self):
        outside = self.outer / "outside"
        (outside / "changelog.d").mkdir(parents=True)
        (outside / "CHANGELOG.md").write_text(BASE)
        (outside / "changelog.d" / "1.fixed.md").write_text("x")
        link = self.root / "link"
        try:
            os.symlink(outside, link, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks unavailable")
        r = run(self.root, "--root", "link")
        self.assertEqual(r.returncode, 2, r.stderr)
        self.assertTrue((outside / "changelog.d" / "1.fixed.md").exists())

    def test_root_subdirectory_allowed(self):
        r = run(self.outer, "--root", "repo", "--dry-run")
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_missing_unreleased_section(self):
        self.write_changelog("# Changelog\n\n## [1.0]\n- x\n")
        self.frag("1.fixed.md")
        r = run(self.root)
        self.assertEqual(r.returncode, 1)
        self.assertIn("Unreleased", r.stderr)
        self.assertNotIn("Traceback", r.stderr)

    def test_missing_changelog_dir_and_file(self):
        self.frag("1.fixed.md")
        (self.root / "CHANGELOG.md").unlink()
        r = run(self.root)
        self.assertEqual(r.returncode, 1)
        self.assertIn("CHANGELOG.md", r.stderr)
        r = run(self.outer / "repo" / "changelog.d", "--root", ".", "--dry-run")
        self.assertEqual(r.returncode, 1)
        self.assertIn("changelog.d", r.stderr)

    def test_invalid_fragments(self):
        cases = {
            "bad name": ("1.bogus.md", "x"),
            "empty": ("1.fixed.md", "  \n"),
            "multi-line": ("1.fixed.md", "a\nb"),
            "non-utf8": ("1.fixed.md", b"\xff\xfe\xfa"),
        }
        for label, (name, data) in cases.items():
            with self.subTest(label):
                self.frag(name, data)
                r = run(self.root)
                self.assertEqual(r.returncode, 1, r.stderr)
                self.assertNotIn("Traceback", r.stderr)
                self.assertEqual(self.changelog(), BASE)
                (self.root / "changelog.d" / name).unlink()

    def test_no_fragments(self):
        r = run(self.root)
        self.assertEqual(r.returncode, 0)
        self.assertIn("no fragments", r.stdout)


if __name__ == "__main__":
    unittest.main()
