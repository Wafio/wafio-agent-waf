#!/usr/bin/env python3
"""Tests of the lockfile parser and the pass, fail and offline paths of advisories.py."""
import contextlib
import io
import os
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

import advisories

CARGO = """\
version = 4

[[package]]
name = "ours"
version = "0.1.0"
dependencies = ["serde"]

[[package]]
name = "serde"
version = "1.0.200"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "abc"

[[package]]
name = "fromgit"
version = "0.2.0"
source = "git+https://example.invalid/x#abc"
"""

class Advisories(unittest.TestCase):
    def test_parser(self):
        self.assertEqual(advisories.parse_cargo(CARGO), {("crates.io", "serde", "1.0.200")})

    def run_main(self, allow_text, query):
        with tempfile.TemporaryDirectory() as d:
            lock, allow = os.path.join(d, "Cargo.lock"), os.path.join(d, "advisories.allow")
            Path(lock).write_text(CARGO)
            Path(allow).write_text(allow_text)
            with mock.patch.object(advisories, "query", query), contextlib.redirect_stdout(io.StringIO()):
                return advisories.main(lock, allow)

    def test_allowlist_and_offline(self):
        hit = lambda pkgs: [("RUSTSEC-2000-0001", "serde", "1.0.200")]
        row = "RUSTSEC-2000-0001 | serde | unmaintained, no fixed version | 2026-11-15\n"
        self.assertEqual(self.run_main("# none\n", hit), 1)
        self.assertEqual(self.run_main(row, hit), 0)
        self.assertEqual(self.run_main(row, lambda pkgs: []), 0)

        def offline(pkgs):
            raise urllib.error.URLError("no route")

        self.assertEqual(self.run_main("", offline), 0)
        with self.assertRaises(SystemExit):
            self.run_main("RUSTSEC-2000-0001 | serde | no date\n", hit)


if __name__ == "__main__":
    unittest.main()
