#!/usr/bin/env python3
"""Write the notices of the third-party code in the wafio-waf-agent binary, and optionally its SBOM.

    scripts/gen-notices.py [-o FILE] [--spdx FILE]      run where cargo is (scripts/build-dist.sh calls it)

The engine repository builds the official binary from this repository's crates and its own. Its
scripts/gen-notices.py calls this one with --manifest, --package, --binary and --also, so that the
crates, the adapted code and the texts of both repositories land in one file. When the engine is in a
library instead of in the binary, it names both packages (--package twice, the binary first) and the
file of the library (--library), and the file describes the two files together.

The file has these parts:
  - the crates the agent binary links for x86_64-unknown-linux-gnu, from `cargo tree` (the normal
    dependencies of the wafio-waf-agent package, proc-macro crates included), with their licence fields
    and source directories from `cargo metadata`. Crates used only to build (build scripts) or to test,
    and the crates of the workspace itself, are left out. For each crate it copies the licence and notice
    files found in the crate source that cargo fetched (the top directory, a LICENSES directory, and
    vendored C sources up to three levels down). Identical texts are printed once, with the list of
    crates that carry them;
  - the Rust standard library, the crates linked from other repositories (the uddin interpreter), the
    code adapted from other projects, the copyright lines that exist only in source file headers, and the
    runtime data the agent downloads. These come from scripts/notices/notices.json and the verbatim
    licence texts in scripts/notices/texts/.
The output depends on Cargo.lock and those two places only: the same inputs give the same file.

--spdx writes the SBOM of the same build as SPDX 2.3 JSON: the crates above plus the crates from other
repositories, each with the licence its Cargo.toml declares, and the file or files that contain them. It
holds what the binaries link and nothing else: the tree it is made from has no dev-dependency, no build
dependency and no proc-macro crate (nor a crate only a proc-macro crate uses), which are tools of the build
and are not in the binaries. The notices keep the proc-macro crates, as said above. Only the time and the
document namespace change from run to run.

It exits with an error, which fails scripts/ci-local.sh, when
  - a linked crate has no licence file and notices.json does not borrow one for it
    ("licence_from_sibling");
  - a linked crate comes from a checkout other than this one, the workspace being built and the ones named with
    --also, and "linked_path_crates" has no entry for it, or an entry names a crate that is not linked;
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
import datetime
import hashlib
import json
import os
import re
import subprocess
import sys
import textwrap
import uuid

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
BUNDLE = "wafio-waf-agent"  # the name of the release bundle the SBOM goes into: <BUNDLE>-<version>-linux-amd64
CRATES_IO = ("registry+https://github.com/rust-lang/crates.io-index", "sparse+https://index.crates.io/")
# Texts that entries may refer to instead of repeating them: the strings every copy holds.
REFERENCE_MARKERS = {
    "Apache-2.0": ("Apache License", "Version 2.0, January 2004", "END OF TERMS AND CONDITIONS"),
    "Unicode-3.0": ("UNICODE LICENSE V3",),
}


def cargo(*args):
    return subprocess.run(["cargo", *args], check=True, capture_output=True, text=True).stdout


def tree_keys(manifest, package, edges):
    """The (name, version) of every package in the `cargo tree` of PACKAGE for TARGET, the package itself included."""
    tree = cargo("tree", "--locked", "--manifest-path", manifest, "-p", package, "-e", edges,
                 "--target", TARGET, "--prefix", "none", "--format", "{p}")
    return {m.groups() for m in (re.match(r"(\S+) v(\S+)", line) for line in tree.splitlines()) if m}


def linked_crates(manifest, packages):
    """What the packages link for TARGET: (registry crates, other linked crates).

    `cargo tree` resolves the features of one package alone. `cargo metadata` unifies the features of
    every workspace member, so its graph holds crates that only another member (a benchmark, the
    conformance binary) pulls in; it is used only for the licence fields and the source directory.
    The registry crates are what the notices list. The other linked crates are the packages from a path
    (the crates of the workspaces and of the uddin interpreter), among them the packages themselves.
    """
    wanted = set().union(*(tree_keys(manifest, package, "normal") for package in packages))
    meta = json.loads(cargo("metadata", "--format-version", "1", "--locked", "--filter-platform", TARGET,
                            "--manifest-path", manifest))
    known = {(p["name"], p["version"]): p for p in meta["packages"]}
    members = {k for k, p in known.items() if p["source"] is None}
    absent = sorted(wanted - known.keys())
    if absent:
        sys.exit(f"gen-notices: cargo tree lists crates that cargo metadata does not: {absent}")
    return [known[k] for k in sorted(wanted - members)], [known[k] for k in sorted(wanted & members)]


def outside(local, roots):
    """The crates of LOCAL whose source is in none of the directories ROOTS."""
    keep = [os.path.join(os.path.realpath(r), "") for r in roots]
    return [c for c in local if not any(os.path.realpath(c["manifest_path"]).startswith(k) for k in keep)]


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
        out.append(textwrap.fill(e["copyright"], 79, break_long_words=False, break_on_hyphens=False))
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


def header_lines(binary, library, n_crates, n_other, other_heading):
    """The opening paragraph: which files these notices describe and what they link."""
    who = f"The {binary} binary and the {library} library link" if library else f"The {binary} binary links"
    crates = f"the {n_crates} crates below" + (" (the crates of both files together)" if library else "")
    parts = [crates]
    if n_other:
        parts.append(f"the {n_other} crates listed under \"{other_heading}\"")
    parts += ["the Rust standard library", "code adapted from the projects named under \"Code adapted from other projects\""]
    text = (f"{who} {', '.join(parts[:-1])}, and {parts[-1]}. This file is generated by scripts/gen-notices.py from the "
            "licence files in each crate's published source and from scripts/notices/notices.json; do not edit it by hand.")
    return textwrap.fill(text, 79, break_long_words=False, break_on_hyphens=False).split("\n")


def spdx_licence(expr):
    """A Cargo licence field as an SPDX expression. The old "A/B" form means "A OR B"; a reference to a licence
    that is not on the SPDX list has no entry in the document, so it is not asserted."""
    if not expr or "LicenseRef" in expr:
        return "NOASSERTION"
    return re.sub(r"\s*/\s*", " OR ", expr.strip())


def spdx_document(name, version, roots, crates, created, uid):
    """SPDX 2.3 JSON. ROOTS: dicts with name, licence and links (keys of CRATES) for each shipped file.
    CRATES: (name, version) -> dict with licence and optional download, purl and copyright."""
    ids = set()

    def new_id(kind, pname, pversion):
        pid = "SPDXRef-" + kind + "-" + re.sub(r"[^A-Za-z0-9.-]", "-", f"{pname}-{pversion}")
        if pid in ids:
            raise ValueError(f"two packages get the SPDX id {pid}")
        ids.add(pid)
        return pid

    def package(pid, pname, pversion, licence, download="NOASSERTION", copyright_text="NOASSERTION"):
        return {"SPDXID": pid, "name": pname, "versionInfo": pversion, "downloadLocation": download,
                "filesAnalyzed": False, "licenseConcluded": "NOASSERTION", "licenseDeclared": spdx_licence(licence),
                "copyrightText": copyright_text, "supplier": "NOASSERTION"}

    crate_ids, crate_packages = {}, []
    for (cname, cversion), c in sorted(crates.items()):
        pid = crate_ids[(cname, cversion)] = new_id("Crate", cname, cversion)
        pkg = package(pid, cname, cversion, c.get("licence"), c.get("download", "NOASSERTION"), c.get("copyright", "NOASSERTION"))
        if c.get("purl"):
            pkg["externalRefs"] = [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": c["purl"]}]
        crate_packages.append(pkg)
    root_packages, relationships = [], []
    for root in roots:
        pid = new_id("File", root["name"], version)
        root_packages.append(package(pid, root["name"], version, root.get("licence")))
        relationships.append({"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": pid})
        relationships += [{"spdxElementId": pid, "relationshipType": "CONTAINS", "relatedSpdxElement": crate_ids[k]}
                          for k in sorted(root["links"])]
    return {"spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT", "name": name,
            "documentNamespace": f"https://wafio.cloud/spdx/{name}-{uid}",
            "creationInfo": {"created": created, "creators": ["Tool: wafio-gen-notices"]},
            "packages": root_packages + crate_packages, "relationships": relationships}


def crate_entry(c):
    """What the SBOM says about a crate of a registry."""
    info = {"licence": c.get("license")}
    if c.get("source") in CRATES_IO:
        info["download"] = f"https://crates.io/api/v1/crates/{c['name']}/{c['version']}/download"
        info["purl"] = f"pkg:cargo/{c['name']}@{c['version']}"
    return info


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("-o", "--output", help="write here instead of standard output")
    ap.add_argument("--manifest", default=os.path.join(HERE, "..", "Cargo.toml"),
                    help="the workspace that holds the package (default: this repository)")
    ap.add_argument("--package", action="append", metavar="PACKAGE",
                    help=f"the package of the binary (default {ROOT_PACKAGE}); with --library, the package of the library after it")
    ap.add_argument("--binary", default=BINARY, help="the name of the binary in the text (default %(default)s)")
    ap.add_argument("--library", help="the file name of the engine library that ships next to the binary, when there is one")
    ap.add_argument("--spdx", metavar="FILE", help="also write the SBOM of the build here, as SPDX JSON")
    ap.add_argument("--version", default=os.environ.get("WAFIO_AGENT_VERSION", "dev"),
                    help="the version the SBOM names (default $WAFIO_AGENT_VERSION, else dev)")
    ap.add_argument("--also", action="append", default=[], metavar="REPO",
                    help="another checkout whose scripts/notices adds adapted-code entries and texts")
    args = ap.parse_args()
    manifest = args.manifest
    packages = args.package or [ROOT_PACKAGE]
    if len(packages) != 1 + bool(args.library):
        sys.exit("gen-notices: one --package for the binary, and with --library a second one for the library")
    crates, local = linked_crates(manifest, packages)
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

    # Crates from a checkout that is none of the agent's own: each needs an entry with its licence.
    lp = data["linked_path_crates"]
    foreign = outside(local, [*TEXT_ROOTS, os.path.dirname(os.path.abspath(manifest))])
    foreign_names = {c["name"] for c in foreign}
    for e in lp["entries"]:
        mine = [c for c in foreign if c["name"] in e["crates"]]
        e["version"] = ", ".join(sorted({c["version"] for c in mine}))
        e["also"] = ["Crates linked: " + ", ".join(sorted(c["name"] for c in mine)) + "."]
        for n in e["crates"]:
            if n not in foreign_names:
                errors.append(f"linked_path_crates names {n}, which is not linked from another checkout: remove the entry")
    for c in foreign:
        if not any(c["name"] in e["crates"] for e in lp["entries"]):
            errors.append(f"{c['name']} {c['version']} is linked from {os.path.dirname(c['manifest_path'])}, which is not "
                          "a checkout of the agent: add it to linked_path_crates with its licence")

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
        *header_lines(args.binary, args.library, len(crates), len(foreign), lp["heading"]),
        "",
        "Crates (name, version, licence expression declared in Cargo.toml)",
        "-----------------------------------------------------------------",
    ]
    for c in crates:
        out.append(f"{c['name']} {c['version']}  {c.get('license') or 'no licence expression'}")

    out += ["", "The Rust standard library", "-------------------------", ""]
    out += adapted_section(data["runtime_library"], texts, errors, "runtime_library")

    out += [lp["heading"], "-" * len(lp["heading"]), "", *lp["intro"], ""]
    out += adapted_section(lp["entries"], texts, errors, "linked_path_crates")

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
    if args.spdx:
        sbom = {(c["name"], c["version"]): crate_entry(c) for c in crates}
        for c in foreign:
            entry = next(e for e in lp["entries"] if c["name"] in e["crates"])
            sbom[(c["name"], c["version"])] = {"licence": c.get("license"), "download": entry["url"],
                                               "copyright": entry["copyright"]}
        by_package = {c["name"]: c for c in local}
        shipped = {p: tree_keys(manifest, p, "normal,no-proc-macro") for p in packages}
        sbom = {k: v for k, v in sbom.items() if any(k in keys for keys in shipped.values())}
        roots = [{"name": name, "licence": by_package[package].get("license"),
                  "links": {k for k in shipped[package] if k in sbom}}
                 for name, package in zip([args.binary, args.library], packages)]
        created = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        doc = spdx_document(f"{BUNDLE}-{args.version}-linux-amd64", args.version, roots, sbom, created, uuid.uuid4())
        with open(args.spdx, "w", encoding="utf-8") as f:
            json.dump(doc, f, indent=2)
            f.write("\n")
    print(f"gen-notices: {len(crates)} crates and {len(foreign)} from other repositories, {len(texts)} distinct texts, "
          f"{len(ad['entries'])} adapted-code entries, {len(missing)} without a licence file", file=sys.stderr)


if __name__ == "__main__":
    main()
