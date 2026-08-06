#!/usr/bin/env python3
"""Check an npm or pnpm lockfile against the malicious-package CSVs in this repo.

Exit codes: 0 no match, 1 at least one match, 2 usage or data error.
"""

import argparse
import csv
import json
import re
import sys
from pathlib import Path
from typing import NamedTuple

import yaml

try:
    from yaml import CSafeLoader as YamlLoader
except ImportError:  # libyaml not built; falls back to the slower pure-Python loader
    from yaml import SafeLoader as YamlLoader

REPO_ROOT = Path(__file__).resolve().parent.parent

# The CSVs pin exact versions ("1.2.3", "= 1.2.3"). A comparator or wildcard
# cannot be matched against a locked version, so it is reported, not dropped.
EXACT_VERSION_RE = re.compile(r"^v?\d[\w.+-]*$")


class IocData(NamedTuple):
    index: dict  # {package_name: {version: [campaign, ...]}}
    sources: list  # [(csv_path, campaign, package_count)]
    warnings: list  # CSVs that look like package lists but could not be read
    unpinned: list  # version cells that are ranges rather than exact pins


def find_column(fieldnames, predicate):
    for name in fieldnames or []:
        if name and predicate(name.strip().lower()):
            return name
    return None


def parse_versions(cell):
    """Split a version cell into (exact_versions, unpinned_tokens).

    Accepts the formats present in the CSVs: "1.1.7, 1.1.8" and
    "= 0.0.7 || = 0.0.8".
    """
    exact, unpinned = [], []
    for token in re.split(r"\|\||,", cell):
        token = token.strip()
        if token.startswith("="):
            token = token[1:].strip()
        if not token:
            continue
        if EXACT_VERSION_RE.match(token):
            exact.append(token)
        else:
            unpinned.append(token)
    return exact, unpinned


def load_ioc_index(repo_root):
    """Index every CSV in the repo that has a `Package` column.

    The campaign name is the CSV filename stem, so new campaign files are
    picked up without a code change. CSVs without a `Package` column are
    other IOC types (domains, hashes) and are ignored.
    """
    index = {}
    sources, warnings, unpinned = [], [], []

    for csv_path in sorted(Path(repo_root).rglob("*.csv")):
        if ".git" in csv_path.parts:
            continue

        rel = csv_path.relative_to(repo_root).as_posix()

        try:
            with open(csv_path, newline="", encoding="utf-8-sig") as f:
                reader = csv.DictReader(f)
                fieldnames = reader.fieldnames or []

                package_col = find_column(fieldnames, lambda n: n == "package")
                if not package_col:
                    continue

                version_col = find_column(fieldnames, lambda n: "version" in n)
                if not version_col:
                    warnings.append(
                        f"{rel}: has a 'Package' column but no version column "
                        f"(columns: {', '.join(fieldnames)})"
                    )
                    continue

                campaign = csv_path.stem
                package_count = 0

                for row in reader:
                    name = (row.get(package_col) or "").strip()
                    cell = (row.get(version_col) or "").strip()
                    if not name or not cell:
                        continue

                    exact, bad = parse_versions(cell)
                    unpinned.extend(f"{campaign}: {name} {token}" for token in bad)

                    for version in exact:
                        campaigns = index.setdefault(name, {}).setdefault(version, [])
                        if campaign not in campaigns:
                            campaigns.append(campaign)
                    package_count += 1

                sources.append((rel, campaign, package_count))
        except (OSError, UnicodeDecodeError, csv.Error) as exc:
            warnings.append(f"{rel}: could not be read ({exc})")

    return IocData(index, sources, warnings, unpinned)


def parse_package_lock(path):
    """Extract (name, version) pairs from a package-lock.json.

    Handles lockfileVersion 1 (nested `dependencies`) and 2/3 (flat `packages`).
    """
    with open(path, encoding="utf-8") as f:
        data = json.load(f)

    found = set()
    packages = data.get("packages")

    if packages is not None:
        for pkg_path, info in packages.items():
            # Entries without node_modules/ are workspace members, not
            # registry installs.
            if "node_modules/" not in pkg_path:
                continue
            version = info.get("version")
            if version:
                found.add((pkg_path.rsplit("node_modules/", 1)[-1], version))
    else:

        def walk(deps):
            for name, info in (deps or {}).items():
                version = info.get("version")
                if version:
                    found.add((name, version))
                walk(info.get("dependencies"))

        walk(data.get("dependencies"))

    return found


def split_pnpm_key(key):
    """Return (name, version) for a pnpm `packages:` key, or (None, None).

    Covers the key layouts pnpm has used: `/name/1.2.3` (v5),
    `/name@1.2.3` (v6) and `name@1.2.3` (v9). Peer suffixes are stripped.
    """
    key = key.strip().lstrip("/").split("(", 1)[0]
    if not key:
        return None, None

    for separator in ("@", "/"):
        name, found, version = key.rpartition(separator)
        if found and name and EXACT_VERSION_RE.match(version):
            return name, version

    return None, None


def parse_pnpm_lock(path):
    """Extract (name, version) pairs from the `packages:` section of a pnpm-lock.yaml.

    `snapshots:` is ignored: it repeats the same releases keyed by peer context.
    """
    with open(path, encoding="utf-8") as f:
        data = yaml.load(f, Loader=YamlLoader) or {}

    found = set()
    for key in data.get("packages") or {}:
        name, version = split_pnpm_key(str(key))
        if name and version:
            found.add((name, version))
    return found


def read_lockfile(lockfile_path):
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

    for warning in iocs.warnings:
        print(f"warning: {warning}", file=sys.stderr)
    for item in iocs.unpinned:
        print(f"warning: not an exact version, not checked: {item}", file=sys.stderr)

    if not iocs.sources:
        print(f"error: no package CSVs found under {REPO_ROOT}", file=sys.stderr)
        return 2

    try:
        installed = read_lockfile(args.lockfile)
    except (ValueError, OSError, json.JSONDecodeError, yaml.YAMLError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    hits = find_hits(iocs.index, installed)

    lists = ", ".join(f"{campaign} ({count})" for _, campaign, count in iocs.sources)
    print(f"IOC lists: {lists}")
    print(f"Lockfile: {len(installed)} packages")

    if not hits:
        print("No known-malicious packages found.")
        return 0

    print(f"\n{len(hits)} known-malicious package(s):")
    for name, version, campaigns in hits:
        print(f"  {name}@{version}  [{', '.join(campaigns)}]")
    return 1


if __name__ == "__main__":
    sys.exit(main())
