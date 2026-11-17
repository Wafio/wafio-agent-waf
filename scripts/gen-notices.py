#!/usr/bin/env python3
"""Write the notices of the third-party code in the wafio-waf-agent binary.

    scripts/gen-notices.py [-o FILE]        run where cargo is (scripts/build-dist.sh calls it)

The engine repository builds the official binary from this repository's crates and its own. Its
scripts/gen-notices.py calls this one with --manifest, --package, --binary and --also, so that the
crates, the adapted code and the texts of both repositories land in one file.

The file has these parts:
  - the crates the agent binary links for x86_64-unknown-linux-gnu, from `cargo tree` (the normal
    dependencies of the wafio-waf-agent package, proc-macro crates included), with their licence fields
    and source directories from `cargo metadata`. Crates used only to build (build scripts) or to test,
    and the crates of the workspace itself, are left out. For each crate it copies the licence and notice
    files found in the crate source that cargo fetched (the top directory, a LICENSES directory, and
    vendored C sources up to three levels down). Identical texts are printed once, with the list of
    crates that carry them;
  - the Rust standard library, the code adapted from other projects, the copyright lines that exist only
    in source file headers, and the runtime data the agent downloads. These come from
    scripts/notices/notices.json and the verbatim licence texts in scripts/notices/texts/.
The output depends on Cargo.lock and those two places only: the same inputs give the same file.

It exits with an error, which fails scripts/ci-local.sh, when
  - a linked crate has no licence file and notices.json does not borrow one for it
    ("licence_from_sibling");
  - an entry names a file that does not exist: when adapted code is replaced and its files are gone, the
    entry has to be removed on purpose;
  - a licence text file is missing, or does not hold the copyright line the entry claims;
  - a text an entry refers to (Apache-2.0, Unicode-3.0) is not among the crate texts;
  - a crate named in "source_header_notices" or "licence_from_sibling" is no longer linked.

What it does not cover, and what to check by hand when it matters:
  - the Rust standard library and compiler runtime texts beyond what notices.json says; the Rust
    distribution lists them in COPYRIGHT-library.html;
  - glibc and libgcc_s, which the binary loads from the host (dynamic linking), so they are
    not redistributed;
  - whether a licence file really matches the SPDX expression of its crate (taken as is).
"""
import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import textwrap

ROOT_PACKAGE = "wafio-waf-agent"
BINARY = "wafio-waf-agent-open"
TARGET = "x86_64-unknown-linux-gnu"
LICENCE_NAME = re.compile(r"^(licen[cs]e|copying|copyright|notice|unlicen[cs]e|patents)([-_. ].*)?$", re.I)
SKIP_DIRS = {"tests", "test", "benches", "examples", "docs", "doc", "target", ".git", "node_modules"}
CODE_SUFFIXES = (".rs", ".c", ".h", ".cc", ".cpp", ".py", ".js", ".ts", ".json", ".toml", ".sh", ".in")
MAX_DEPTH = 3
HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
DATA_FILE = os.path.join(HERE, "notices", "notices.json")
TEXT_ROOTS = [REPO]  # the repositories whose scripts/notices/texts are searched, this one first
BAR = "=" * 79
RULE = "-" * 79
# Texts that entries may refer to instead of repeating them: the strings every copy holds.
REFERENCE_MARKERS = {
    "Apache-2.0": ("Apache License", "Version 2.0, January 2004", "END OF TERMS AND CONDITIONS"),
    "Unicode-3.0": ("UNICODE LICENSE V3",),
}


def cargo(*args):
    return subprocess.run(["cargo", *args], check=True, capture_output=True, text=True).stdout


def linked_crates(manifest, package):
    """The registry crates in the normal dependency tree of the agent for TARGET.

    `cargo tree` resolves the features of the agent alone. `cargo metadata` unifies the features of
    every workspace member, so its graph holds crates that only another member (a benchmark, the
    conformance binary) pulls in; it is used only for the licence fields and the source directory.
    """
    tree = cargo("tree", "--locked", "--manifest-path", manifest, "-p", package, "-e", "normal",
                 "--target", TARGET, "--prefix", "none", "--format", "{p}")
    wanted = {m.groups() for m in (re.match(r"(\S+) v(\S+)", line) for line in tree.splitlines()) if m}
    meta = json.loads(cargo("metadata", "--format-version", "1", "--locked", "--filter-platform", TARGET,
                            "--manifest-path", manifest))
    packages = {(p["name"], p["version"]): p for p in meta["packages"]}
    members = {(p["name"], p["version"]) for p in meta["packages"] if p["source"] is None}
    absent = sorted(wanted - members - packages.keys())
    if absent:
        sys.exit(f"gen-notices: cargo tree lists crates that cargo metadata does not: {absent}")
    return [packages[k] for k in sorted(wanted - members)]


def licence_files(crate):
    """Paths of the licence and notice files in the crate source, relative to its directory."""
    base = os.path.dirname(crate["manifest_path"])
    found = set()
    if crate.get("license_file"):
        path = os.path.join(base, crate["license_file"])
        if os.path.isfile(path):
            found.add(os.path.relpath(path, base))
    for dirpath, dirnames, filenames in os.walk(base):
        depth = os.path.relpath(dirpath, base).count(os.sep) + (0 if dirpath == base else 1)
        dirnames[:] = sorted(d for d in dirnames if d.lower() not in SKIP_DIRS) if depth < MAX_DEPTH else []
        for name in filenames:
            if LICENCE_NAME.match(name) and not name.lower().endswith(CODE_SUFFIXES):
                found.add(os.path.relpath(os.path.join(dirpath, name), base))
        if os.path.basename(dirpath).lower() in ("licenses", "licences"):
            for name in filenames:
                found.add(os.path.relpath(os.path.join(dirpath, name), base))
    return sorted(found)


def read_text(name, errors):
    for root in TEXT_ROOTS:
        path = os.path.join(root, "scripts", "notices", "texts", name)
        if os.path.isfile(path):
            with open(path, encoding="utf-8") as f:
                return f.read().strip("\n") + "\n"
    errors.append(f"licence text file missing: scripts/notices/texts/{name}")
    return ""


def squash(text):
    return " ".join(text.split())


def wrap(prefix, items):
    return textwrap.fill(prefix + "; ".join(items), 79, break_long_words=False, break_on_hyphens=False)


def find_reference(texts, name):
    """The key of the text that holds every marker of NAME: the one most crates share, so the plain licence."""
    markers = REFERENCE_MARKERS[name]
    found = [(len(users), key) for key, (text, users) in texts.items() if all(m in text for m in markers)]
    return max(found, key=lambda e: (e[0], e[1]))[1] if found else None


def entry_lines(e):
    out = [RULE, e["name"] + (f"  {e['version']}" if e.get("version") else "")]
    if e.get("url"):
        out.append(e["url"])
    if e.get("copyright"):
        out.append(e["copyright"])
    if e.get("licence"):
        out.append(f"Licence: {e['licence']}")
    for key, label in (("used_for", "Used for"), ("changes", "Changes")):
        if e.get(key):
            out.append(textwrap.fill(f"{label}: {e[key]}", 79, break_long_words=False, break_on_hyphens=False))
    if e.get("files"):
        out.append(textwrap.fill("Files: " + ", ".join(e["files"]), 79, subsequent_indent="  ",
                                 break_long_words=False, break_on_hyphens=False))
    for para in e.get("also", []):
        out.append(textwrap.fill(para, 79, break_long_words=False, break_on_hyphens=False))
    return out


def adapted_section(entries, texts, errors, label):
    """Lines for a list of entries that carry a licence text (inline file, notice or reference)."""
    out = []
    for e in entries:
        out += entry_lines(e)
        for f in e.get("files", []):
            if not any(os.path.exists(os.path.join(root, f)) for root in e.get("roots", [REPO])):
                errors.append(f"{label} entry '{e['name']}': file {f} does not exist; "
                              "if the code was replaced, remove the entry on purpose")
        if "licence_file" in e:
            text = read_text(e["licence_file"], errors)
            # The entry may add a remark in parentheses after the licence's own copyright line.
            check = e["copyright"].split(" (the ")[0]
            if text and squash(check) not in squash(text):
                errors.append(f"{label} entry '{e['name']}': {e['licence_file']} does not hold the line '{check}'")
            out += ["", text.rstrip("\n")]
        elif "notice" in e:
            out += ["", *e["notice"]]
        elif "text_ref" in e:
            key = find_reference(texts, e["text_ref"])
            if key is None:
                errors.append(f"{label} entry '{e['name']}': no {e['text_ref']} text among the crate texts")
            else:
                texts[key][1].append(f"{e['name']} (adapted code)")
                out.append(f"The full {e['text_ref']} text is listed under \"Licence and notice texts\" below.")
        out.append("")
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("-o", "--output", help="write here instead of standard output")
    ap.add_argument("--manifest", default=os.path.join(HERE, "..", "Cargo.toml"),
                    help="the workspace that holds the package (default: this repository)")
    ap.add_argument("--package", default=ROOT_PACKAGE, help="the package of the binary (default %(default)s)")
    ap.add_argument("--binary", default=BINARY, help="the name of the binary in the text (default %(default)s)")
    ap.add_argument("--also", action="append", default=[], metavar="REPO",
                    help="another checkout whose scripts/notices adds adapted-code entries and texts")
    args = ap.parse_args()
    manifest = args.manifest
    crates = linked_crates(manifest, args.package)
    with open(DATA_FILE, encoding="utf-8") as f:
        data = json.load(f)
    for e in data["adapted"]["entries"]:
        e["roots"] = [REPO]
    # Adapted code that sits in the crates of another checkout: its entries are added, and an entry of the same
    # name gets the files of both (the Go standard library ports live on both sides).
    by_name = {e["name"]: e for e in data["adapted"]["entries"]}
    for other in args.also:
        other = os.path.abspath(other)
        TEXT_ROOTS.append(other)
        with open(os.path.join(other, "scripts", "notices", "notices.json"), encoding="utf-8") as f:
            more = json.load(f)
        for e in more["adapted"]["entries"]:
            mine = by_name.get(e["name"])
            if mine is None:
                e["roots"] = [other]
                data["adapted"]["entries"].append(e)
                by_name[e["name"]] = e
            else:
                mine["files"] = e.get("files", []) + mine.get("files", [])
                mine["roots"].append(other)
    errors = []
    names = {c["name"] for c in crates}

    sibling = data.get("licence_from_sibling", {})
    for crate, donor in sorted(sibling.items()):
        for n in (crate, donor):
            if n not in names:
                errors.append(f"licence_from_sibling names {n}, which is not linked: remove the entry")

    texts = {}  # sha256 -> [text, [crate labels]]
    missing = []

    def add_text(raw, user):
        text = raw.decode("utf-8", errors="replace").strip("\n") + "\n"
        key = hashlib.sha256(text.encode()).hexdigest()
        texts.setdefault(key, [text, []])[1].append(user)

    for crate in crates:
        label = f"{crate['name']} {crate['version']}"
        files = licence_files(crate)
        base = os.path.dirname(crate["manifest_path"])
        for rel in files:
            with open(os.path.join(base, rel), "rb") as f:
                add_text(f.read(), f"{label} ({rel})")
        if not files and crate["name"] in sibling:
            for donor in (d for d in crates if d["name"] == sibling[crate["name"]]):
                dbase = os.path.dirname(donor["manifest_path"])
                for rel in licence_files(donor):
                    with open(os.path.join(dbase, rel), "rb") as f:
                        add_text(f.read(), f"{label} (text of {donor['name']} {donor['version']}, {rel})")
            files = [None]
        if not files:
            missing.append(crate)
    for c in missing:
        errors.append(f"{c['name']} {c['version']} ({c.get('license') or 'no licence expression'}) has no "
                      f"licence file: add it to licence_from_sibling or to a notices.json section")

    out = [
        "WAFio WAF agent: third-party notices",
        "====================================",
        "",
        f"The {args.binary} binary links the {len(crates)} crates below, the Rust standard library, and code",
        "adapted from the projects named under \"Code adapted from other projects\". This file is generated by",
        "scripts/gen-notices.py from the licence files in each crate's published source and from",
        "scripts/notices/notices.json; do not edit it by hand.",
        "",
        "Crates (name, version, licence expression declared in Cargo.toml)",
        "-----------------------------------------------------------------",
    ]
    for c in crates:
        out.append(f"{c['name']} {c['version']}  {c.get('license') or 'no licence expression'}")

    out += ["", "The Rust standard library", "-------------------------", ""]
    out += adapted_section(data["runtime_library"], texts, errors, "runtime_library")

    ad = data["adapted"]
    out += [ad["heading"], "-" * len(ad["heading"]), "", *ad["intro"], ""]
    out += adapted_section(ad["entries"], texts, errors, "adapted")

    sh = data["source_header_notices"]
    out += [sh["heading"], "-" * len(sh["heading"]), "", *sh["intro"], ""]
    for e in sh["entries"]:
        for n in e["crates"]:
            if n not in names:
                errors.append(f"source_header_notices names {n}, which is not linked: remove the entry")
        out += [RULE, ", ".join(e["crates"]), f"Where: {e['where']}"]
        out += e.get("lines", [])
        if "licence_file" in e:
            out += ["", read_text(e["licence_file"], errors).rstrip("\n")]
        if e.get("licence_note"):
            out.append(e["licence_note"])
        out.append("")

    rd = data["runtime_data"]
    out += [rd["heading"], "-" * len(rd["heading"]), "", *rd["intro"], ""]
    for e in rd["entries"]:
        out += [RULE, e["name"], e["url"], *e["lines"]]
        if "licence_file" in e:
            out += ["", read_text(e["licence_file"], errors).rstrip("\n")]
        out.append("")

    if errors:
        sys.exit("gen-notices: " + "\n gen-notices: ".join(errors))

    out += ["Licence and notice texts", "------------------------"]
    for text, users in sorted(texts.values(), key=lambda e: e[1][0]):
        out += ["", BAR, wrap("Used by: ", sorted(users)), BAR, "", text.rstrip("\n")]
    body = "\n".join(out) + "\n"

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(body)
    else:
        sys.stdout.write(body)
    print(f"gen-notices: {len(crates)} crates, {len(texts)} distinct texts, "
          f"{len(ad['entries'])} adapted-code entries, {len(missing)} without a licence file", file=sys.stderr)


if __name__ == "__main__":
    main()
