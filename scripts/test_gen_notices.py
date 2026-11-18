#!/usr/bin/env python3
"""Tests of the parts of gen-notices.py that need no cargo: the opening paragraph, the SBOM and the path crate check."""
import importlib.util
import os
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("gen_notices", os.path.join(HERE, "gen-notices.py"))
gen = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gen)

HEADING = "Crates from other repositories"


class Header(unittest.TestCase):
    def test_one_binary(self):
        text = " ".join(gen.header_lines("wafio-waf-agent", None, 237, 5, HEADING))
        self.assertIn("The wafio-waf-agent binary links the 237 crates below, the 5 crates listed under", text)
        self.assertNotIn("both files", text)

    def test_binary_and_library(self):
        text = " ".join(gen.header_lines("wafio-waf-agent", "libwafio_semantic_engine.so", 237, 5, HEADING))
        self.assertIn("The wafio-waf-agent binary and the libwafio_semantic_engine.so library link the 237 crates below "
                      "(the crates of both files together)", text)

    def test_lines_fit(self):
        for line in gen.header_lines("wafio-waf-agent", "libwafio_semantic_engine.so", 237, 5, HEADING):
            self.assertLessEqual(len(line), 79)


class Licence(unittest.TestCase):
    def test_expressions(self):
        self.assertEqual(gen.spdx_licence("MIT/Apache-2.0"), "MIT OR Apache-2.0")
        self.assertEqual(gen.spdx_licence("Apache-2.0 WITH LLVM-exception"), "Apache-2.0 WITH LLVM-exception")
        self.assertEqual(gen.spdx_licence(None), "NOASSERTION")
        self.assertEqual(gen.spdx_licence("LicenseRef-Private"), "NOASSERTION")


class Sbom(unittest.TestCase):
    CRATES = {
        ("serde", "1.0.200"): {"licence": "MIT OR Apache-2.0", "purl": "pkg:cargo/serde@1.0.200",
                               "download": "https://crates.io/api/v1/crates/serde/1.0.200/download"},
        ("only_in_lib", "0.1.0"): {"licence": "MIT"},
        ("uddin", "0.1.0"): {"licence": "MIT", "download": "https://github.com/Wafio/uddin-lang-rs",
                             "copyright": "Copyright (c) 2025 Uddin-Lang Contributors"},
    }
    ROOTS = [{"name": "wafio-waf-agent", "licence": "GPL-3.0-only", "links": {("serde", "1.0.200"), ("uddin", "0.1.0")}},
             {"name": "libwafio_semantic_engine.so", "licence": "LicenseRef-X", "links": {("only_in_lib", "0.1.0")}}]

    def doc(self):
        return gen.spdx_document("wafio-waf-agent-v2.1.0-linux-amd64", "v2.1.0", self.ROOTS, self.CRATES, "2026-11-18T00:00:00Z", "id")

    def test_lists_the_crates_and_the_files(self):
        d = self.doc()
        self.assertEqual(d["spdxVersion"], "SPDX-2.3")
        self.assertEqual([p["name"] for p in d["packages"]],
                         ["wafio-waf-agent", "libwafio_semantic_engine.so", "only_in_lib", "serde", "uddin"])
        serde = next(p for p in d["packages"] if p["name"] == "serde")
        self.assertEqual(serde["externalRefs"][0]["referenceLocator"], "pkg:cargo/serde@1.0.200")
        self.assertEqual(serde["licenseDeclared"], "MIT OR Apache-2.0")
        uddin = next(p for p in d["packages"] if p["name"] == "uddin")
        self.assertEqual(uddin["copyrightText"], "Copyright (c) 2025 Uddin-Lang Contributors")

    def test_each_file_contains_its_own_crates(self):
        d = self.doc()
        ids = {p["SPDXID"]: p["name"] for p in d["packages"]}
        contains = {}
        for r in d["relationships"]:
            if r["relationshipType"] == "CONTAINS":
                contains.setdefault(ids[r["spdxElementId"]], set()).add(ids[r["relatedSpdxElement"]])
        self.assertEqual(contains["wafio-waf-agent"], {"serde", "uddin"})
        self.assertEqual(contains["libwafio_semantic_engine.so"], {"only_in_lib"})
        described = {ids[r["relatedSpdxElement"]] for r in d["relationships"] if r["relationshipType"] == "DESCRIBES"}
        self.assertEqual(described, {"wafio-waf-agent", "libwafio_semantic_engine.so"})

    def test_a_licence_that_is_not_on_the_list_is_not_asserted(self):
        d = self.doc()
        self.assertEqual(next(p for p in d["packages"] if p["name"] == "libwafio_semantic_engine.so")["licenseDeclared"], "NOASSERTION")

    def test_two_crates_with_one_id_fail(self):
        crates = {("a_b", "1"): {}, ("a-b", "1"): {}}
        with self.assertRaises(ValueError):
            gen.spdx_document("n", "v1", [], crates, "t", "u")


class Registry(unittest.TestCase):
    def test_only_crates_io_gets_a_download_and_a_purl(self):
        info = gen.crate_entry({"name": "serde", "version": "1.0.200", "license": "MIT",
                                "source": "registry+https://github.com/rust-lang/crates.io-index"})
        self.assertEqual(info["purl"], "pkg:cargo/serde@1.0.200")
        self.assertEqual(gen.crate_entry({"name": "x", "version": "1", "license": "MIT", "source": "git+https://example.com/x"}),
                         {"licence": "MIT"})


class Outside(unittest.TestCase):
    def test_a_crate_beside_the_checkouts_is_outside(self):
        mine = {"name": "wafio-proxy", "manifest_path": "/w/wafio-agent-waf/crates/proxy/Cargo.toml"}
        uddin = {"name": "uddin", "manifest_path": "/w/uddin-lang-rs/crates/uddin/Cargo.toml"}
        self.assertEqual(gen.outside([mine, uddin], ["/w/wafio-agent-waf", "/w/wafio-semantic-engine"]), [uddin])

    def test_a_sibling_with_the_same_name_start_is_not_inside(self):
        other = {"name": "x", "manifest_path": "/w/wafio-agent-waf-extra/crates/x/Cargo.toml"}
        self.assertEqual(gen.outside([other], ["/w/wafio-agent-waf"]), [other])


if __name__ == "__main__":
    unittest.main()
