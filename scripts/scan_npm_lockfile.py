#!/usr/bin/env python3
"""Check an npm or pnpm lockfile against the malicious-package CSVs in this repo.

Exit codes: 0 no match, 1 at least one match, 2 no verdict (the scan could not
be completed). Anything that makes the check incomplete -- unreadable IOC data,
an unparsable lockfile, zero packages parsed -- is a 2, never a 0.
"""

import argparse
import csv
import json
import re
import sys
import traceback
from pathlib import Path
from typing import NamedTuple

import yaml

try:
    from yaml import CSafeLoader as YamlLoader
except ImportError:  # libyaml not built; falls back to the slower pure-Python loader
    from yaml import SafeLoader as YamlLoader

REPO_ROOT = Path(__file__).resolve().parent.parent

# Numeric components only, with optional prerelease/build metadata. Wildcards
# ("1.x"), comparators (">=1.0.0"), tags ("latest") and git-tag style ("v1.2.3",
# which no lockfile writes) must NOT match: they cannot be compared to a locked
# version.
EXACT_VERSION_RE = re.compile(r"^\d+(?:\.\d+)*(?:[-+][0-9A-Za-z.-]+)?$")

# A pnpm `packages:` key: `name@1.2.3` (v6/v9) or `name/1.2.3` (v5), with an
# optional peer suffix -- `(react@18.2.0)` in v6/v9, `_react@18.2.0` in v5.
PNPM_KEY_RE = re.compile(
    r"^(?P<name>(?:@[^/@]+/)?[^/@]+)"
    r"[@/]"
    r"(?P<version>\d[0-9A-Za-z.+-]*)"
    r"(?:[(_].*)?$"
)

# Preferred exactly; any other header containing "version" is a fallback.
VERSION_COLUMNS = (
    "version",
    "versions",
    "malicious version",
    "malicious versions",
    "affected version",
    "affected versions",
)


class IocData(NamedTuple):
    index: dict  # {package_name: {version: [campaign, ...]}}
    sources: list  # [(campaign, indexed_package_count)]
    warnings: list  # file-level problems; any of these means no verdict
    unchecked: list  # IOC rows that could not be indexed (ranges, blank cells)


def find_columns(fieldnames, predicate):
    return [n for n in fieldnames or [] if n and predicate(n.strip().lower())]


def select_columns(fieldnames):
    """Pick the package and version columns. Returns (package, version, all_version_matches).

    The package column is matched exactly first, then by substring, so a future
    `Package Name` header is still indexed rather than silently skipped.
    """
    packages = find_columns(fieldnames, lambda n: n == "package") or find_columns(
        fieldnames, lambda n: "package" in n
    )
    versions = find_columns(
        fieldnames, lambda n: n in VERSION_COLUMNS
    ) or find_columns(fieldnames, lambda n: "version" in n)
    return (
        packages[0] if packages else None,
        versions[0] if versions else None,
        versions,
    )


def parse_versions(cell):
    """Split a version cell into (exact_versions, unchecked_tokens).

    Accepts the formats present in the CSVs: "1.1.7, 1.1.8" and
    "= 0.0.7 || = 0.0.8". Tokens that are not exact pins are returned for
    reporting rather than dropped.
    """
    exact, unchecked = [], []
    for token in re.split(r"\|\||,", cell):
        token = token.strip()
        if token.startswith("="):
            token = token[1:].strip()
        if not token:
            continue
        if EXACT_VERSION_RE.match(token):
            exact.append(token)
        else:
            unchecked.append(token)
    return exact, unchecked


def load_ioc_index(repo_root):
    """Index every CSV in the repo that has a package column.

    The campaign name is the CSV filename stem, so new campaign files are
    picked up without a code change. CSVs with neither a package nor a version
    column are other IOC types (domains, hashes) and are ignored silently.

    A file's rows are staged and merged only once it has been read to the end,
    so a read error part-way through contributes nothing rather than leaving a
    partial campaign in the index.
    """
    index = {}
    sources, warnings, unchecked = [], [], []

    for csv_path in sorted(Path(repo_root).rglob("*.csv")):
        if ".git" in csv_path.parts:
            continue

        rel = csv_path.relative_to(repo_root).as_posix()
        campaign = csv_path.stem
        staged, staged_unchecked = {}, []

        try:
            with open(csv_path, newline="", encoding="utf-8-sig") as f:
                reader = csv.DictReader(f)
                fieldnames = reader.fieldnames or []
                package_col, version_col, version_matches = select_columns(fieldnames)

                if not package_col:
                    if version_col:
                        warnings.append(
                            f"{rel}: has a version column but no package column "
                            f"(columns: {', '.join(fieldnames)})"
                        )
                    continue

                if not version_col:
                    warnings.append(
                        f"{rel}: has a package column but no version column "
                        f"(columns: {', '.join(fieldnames)})"
                    )
                    continue

                if len(version_matches) > 1:
                    warnings.append(
                        f"{rel}: ambiguous version columns "
                        f"({', '.join(version_matches)}); would use '{version_col}'"
                    )
                    continue

                for row in reader:
                    name = (row.get(package_col) or "").strip()
                    cell = (row.get(version_col) or "").strip()

                    if not name and not cell:
                        continue
                    if not name:
                        staged_unchecked.append(f"{rel} line {reader.line_num}: version with no package name")
                        continue
                    if not cell:
                        staged_unchecked.append(f"{rel} line {reader.line_num}: {name} has no version")
                        continue

                    exact, bad = parse_versions(cell)
                    staged_unchecked.extend(f"{rel}: {name} {token}" for token in bad)
                    for version in exact:
                        staged.setdefault(name, set()).add(version)
        except (OSError, UnicodeDecodeError, csv.Error) as exc:
            warnings.append(f"{rel}: could not be read ({exc})")
            continue

        for name, versions in staged.items():
            for version in sorted(versions):
                campaigns = index.setdefault(name, {}).setdefault(version, [])
                if campaign not in campaigns:
                    campaigns.append(campaign)

        unchecked.extend(staged_unchecked)
        sources.append((campaign, len(staged)))

    return IocData(index, sources, warnings, unchecked)


def parse_package_lock(path):
    """Extract (name, version) pairs from a package-lock.json.

    Handles lockfileVersion 1 (nested `dependencies`) and 2/3 (flat `packages`).
    Returns (found, unparsed).
    """
    with open(path, encoding="utf-8") as f:
        data = json.load(f)

    found, unparsed = set(), []
    packages = data.get("packages")

    if packages is not None:
        for pkg_path, info in packages.items():
            # "" is the root project and other keys without node_modules/ are
            # workspace members; neither is a registry install.
            if "node_modules/" not in pkg_path:
                continue
            # "link": true is a symlink to a workspace member, whose own entry
            # is the non-node_modules/ key skipped above.
            if info.get("link"):
                continue
            version = info.get("version")
            if not version:
                unparsed.append(pkg_path)
                continue
            # npm records the real package under "name" for an alias install
            # (`npm i cjs-copy@npm:strip-ansi`), where the path holds the alias.
            found.add((info.get("name") or pkg_path.rsplit("node_modules/", 1)[-1], version))
    else:

        def walk(deps):
            for name, info in (deps or {}).items():
                version = info.get("version")
                if version:
                    # lockfileVersion 1 encodes an alias as "npm:real-name@1.2.3".
                    if version.startswith("npm:"):
                        real_name, _, real_version = version[4:].rpartition("@")
                        if real_name and real_version:
                            name, version = real_name, real_version
                        else:
                            unparsed.append(f"{name}: {version}")
                            continue
                    found.add((name, version))
                walk(info.get("dependencies"))

        walk(data.get("dependencies"))

    return found, unparsed


def split_pnpm_key(key):
    """Return (name, version) for a pnpm `packages:` key, or (None, None).

    Covers the layouts pnpm has used -- `/name/1.2.3` (v5), `/name@1.2.3` (v6)
    and `name@1.2.3` (v9) -- and strips both peer-suffix forms. Keys that do not
    resolve to a registry name and version (git, tarball and `catalog:` entries)
    return (None, None) so the caller can report them.
    """
    match = PNPM_KEY_RE.match(key.strip().lstrip("/"))
    if not match:
        return None, None
    return match.group("name"), match.group("version")


def parse_pnpm_lock(path):
    """Extract (name, version) pairs from the `packages:` section of a pnpm-lock.yaml.

    `snapshots:` is ignored: it repeats the same releases keyed by peer context.
    Returns (found, unparsed).
    """
    with open(path, encoding="utf-8") as f:
        data = yaml.load(f, Loader=YamlLoader) or {}

    found, unparsed = set(), []
    for key in data.get("packages") or {}:
        name, version = split_pnpm_key(str(key))
        if name and version:
            found.add((name, version))
        else:
            unparsed.append(str(key))
    return found, unparsed


def read_lockfile(lockfile_path):
    """Dispatch on the exact filename. Returns (found, unparsed)."""
    path = Path(lockfile_path)
    if path.name == "package-lock.json":
        return parse_package_lock(path)
    if path.name == "pnpm-lock.yaml":
        return parse_pnpm_lock(path)
    raise ValueError(
        f"unsupported lockfile '{path.name}': expected package-lock.json or pnpm-lock.yaml"
    )


def find_hits(index, installed):
    """Return sorted (name, version, campaigns) for locked packages that match."""
    return sorted(
        (name, version, index[name][version])
        for name, version in installed
        if version in index.get(name, {})
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("lockfile", help="path to package-lock.json or pnpm-lock.yaml")
    args = parser.parse_args()

    iocs = load_ioc_index(REPO_ROOT)

    for item in iocs.unchecked:
        print(f"warning: IOC entry not checked: {item}", file=sys.stderr)
    for warning in iocs.warnings:
        print(f"error: {warning}", file=sys.stderr)

    if iocs.warnings:
        print(
            "error: IOC data is incomplete, no verdict produced", file=sys.stderr
        )
        return 2

    if not iocs.index:
        print(
            f"error: no malicious-package CSVs found under {REPO_ROOT}, "
            "no verdict produced",
            file=sys.stderr,
        )
        return 2

    try:
        installed, unparsed = read_lockfile(args.lockfile)
    except (ValueError, OSError, AttributeError, TypeError, yaml.YAMLError) as exc:
        print(
            f"error: could not read lockfile {args.lockfile}: {exc}; "
            "no verdict produced",
            file=sys.stderr,
        )
        return 2

    if not installed:
        print(
            f"error: parsed 0 packages from {args.lockfile}; the file is empty or "
            "its format is not recognised, no verdict produced",
            file=sys.stderr,
        )
        return 2

    for key in unparsed:
        print(f"warning: lockfile entry not checked: {key}", file=sys.stderr)

    lists = ", ".join(f"{campaign} ({count})" for campaign, count in iocs.sources)
    print(f"IOC lists: {lists}")
    print(
        f"Lockfile: {len(installed)} packages"
        + (f", {len(unparsed)} entries not checked" if unparsed else "")
    )

    hits = find_hits(iocs.index, installed)
    if not hits:
        print("No known-malicious packages found.")
        return 0

    print(f"\n{len(hits)} known-malicious package(s):")
    for name, version, campaigns in hits:
        print(f"  {name}@{version}  [{', '.join(campaigns)}]")
    return 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:
        # Never let an unexpected exception exit 1 -- that is the "match found" code.
        traceback.print_exc()
        print("error: scan aborted, no verdict produced", file=sys.stderr)
        sys.exit(2)
