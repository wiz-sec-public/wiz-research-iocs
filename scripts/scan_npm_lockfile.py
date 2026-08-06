#!/usr/bin/env python3
"""Scan an npm lockfile for packages listed in this repo's supply-chain IOC CSVs.

Reads the campaign CSVs in this repo directly (any CSV with a `Package` column),
so `git pull upstream main` is the only step needed to pick up new or revised
campaign data -- there is no generated file to keep in sync.

Exits 1 if any locked package/version matches a known-malicious release.
"""

import argparse
import csv
import json
import os
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# Upstream pins exact versions ("1.2.3", "= 1.2.3"). Anything else -- a real
# range, wildcard or comparator -- cannot be matched against a locked version,
# so it is reported rather than silently dropped.
EXACT_VERSION_RE = re.compile(r"^v?\d[\w.+-]*$")


def find_column(fieldnames, predicate):
    for name in fieldnames or []:
        if name and predicate(name.strip().lower()):
            return name
    return None


def parse_versions(cell):
    """Split a versions cell into (exact_versions, unsupported_tokens).

    Handles both formats currently used upstream: comma-separated
    ("1.1.7, 1.1.8") and npm-range-ish ("= 0.0.7 || = 0.0.8").
    """
    exact, unsupported = [], []
    for token in re.split(r"\|\||,", cell):
        token = token.strip()
        if token.startswith("="):
            token = token[1:].strip()
        if not token:
            continue
        if EXACT_VERSION_RE.match(token):
            exact.append(token)
        else:
            unsupported.append(token)
    return exact, unsupported


def load_ioc_index(repo_root):
    """Build {package_name: {version: [campaigns]}} from every package CSV found.

    Returns the index plus bookkeeping so the caller can report what was read,
    what was ignored, and what could not be parsed.
    """
    index = {}
    loaded, skipped, warnings, unsupported = [], [], [], []

    for csv_path in sorted(repo_root.rglob("*.csv")):
        if ".git" in csv_path.parts:
            continue

        rel = csv_path.relative_to(repo_root).as_posix()

        try:
            with open(csv_path, newline="", encoding="utf-8-sig") as f:
                reader = csv.DictReader(f)
                fieldnames = reader.fieldnames or []

                package_col = find_column(fieldnames, lambda n: n == "package")
                if not package_col:
                    skipped.append((rel, "no 'Package' column"))
                    continue

                version_col = find_column(fieldnames, lambda n: "version" in n)
                if not version_col:
                    # Looks like a package list but we cannot tell which column
                    # holds versions -- surface it instead of ignoring it.
                    warnings.append(
                        f"{rel}: has a 'Package' column but no recognisable "
                        f"version column (columns: {', '.join(fieldnames)})"
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
                    unsupported.extend(f"{campaign}: {name} -> {tok}" for tok in bad)

                    for version in exact:
                        campaigns = index.setdefault(name, {}).setdefault(version, [])
                        if campaign not in campaigns:
                            campaigns.append(campaign)
                    package_count += 1

                loaded.append((rel, campaign, package_count))
        except (OSError, UnicodeDecodeError, csv.Error) as exc:
            warnings.append(f"{rel}: could not be read ({exc})")

    return index, loaded, skipped, warnings, unsupported


def parse_package_lock(path):
    with open(path, encoding="utf-8") as f:
        data = json.load(f)

    found = set()
    packages = data.get("packages")

    if packages is not None:
        # lockfileVersion 2/3: flat map keyed by "node_modules/..." path
        for pkg_path, info in packages.items():
            if not pkg_path:
                continue  # the root project entry
            version = info.get("version")
            if version:
                found.add((pkg_path.rsplit("node_modules/", 1)[-1], version))
    else:
        # lockfileVersion 1: recursive "dependencies" tree
        def walk(deps):
            for name, info in (deps or {}).items():
                version = info.get("version")
                if version:
                    found.add((name, version))
                walk(info.get("dependencies"))

        walk(data.get("dependencies"))

    return found


def split_pnpm_key(key):
    """Split a pnpm `packages:` key ('@scope/name@1.2.3' or 'name@1.2.3')
    into (name, version), or (None, None) if it does not look like one."""
    if key.startswith("@"):
        rest = key[1:]
        if "@" not in rest:
            return None, None
        scope_name, version = rest.split("@", 1)
        return f"@{scope_name}", version
    if "@" not in key:
        return None, None
    name, version = key.split("@", 1)
    return name, version


def parse_pnpm_lock(path):
    """Best-effort line scan of the `packages:` section of a pnpm-lock.yaml.

    Deliberately avoids a PyYAML dependency; does not attempt to cover every
    pnpm lockfile version's quirks.
    """
    found = set()
    in_packages_section = False

    with open(path, encoding="utf-8") as f:
        for raw_line in f:
            line = raw_line.rstrip("\n")
            if not line.strip():
                continue

            indent = len(line) - len(line.lstrip(" "))
            stripped = line.strip()

            if indent == 0:
                in_packages_section = stripped.rstrip(":") == "packages"
                continue

            if not in_packages_section or indent != 2 or not stripped.endswith(":"):
                continue

            key = stripped[:-1].strip().strip("'\"").lstrip("/")
            name, version_part = split_pnpm_key(key)
            if not name or not version_part:
                continue

            found.add((name, version_part.split("(")[0]))  # strip peer-dep suffix

    return found


def read_lockfile(lockfile_path):
    path = Path(lockfile_path)
    if path.name == "package-lock.json":
        return parse_package_lock(path)
    if path.name == "pnpm-lock.yaml":
        return parse_pnpm_lock(path)
    raise SystemExit(
        f"Unsupported lockfile '{path.name}': "
        "expected package-lock.json or pnpm-lock.yaml"
    )


def export_json(index, loaded):
    campaigns = {}
    for name, versions in index.items():
        for version, campaign_ids in versions.items():
            for campaign_id in campaign_ids:
                campaigns.setdefault(campaign_id, {}).setdefault(name, []).append(version)

    return {
        "description": "Malicious npm packages derived from this repo's IOC CSVs.",
        "sources": [{"file": rel, "campaign": campaign} for rel, campaign, _ in loaded],
        "campaigns": [
            {
                "id": campaign_id,
                "package_count": len(packages),
                "packages": {n: sorted(v) for n, v in sorted(packages.items())},
            }
            for campaign_id, packages in sorted(campaigns.items())
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "lockfile",
        nargs="?",
        help="Path to package-lock.json or pnpm-lock.yaml",
    )
    parser.add_argument(
        "--repo-root",
        default=REPO_ROOT,
        type=Path,
        help=f"Repo root to search for IOC CSVs (default: {REPO_ROOT})",
    )
    parser.add_argument(
        "--export-json",
        metavar="PATH",
        help="Write the normalised IOC data to PATH ('-' for stdout) and exit",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Also list CSVs that were skipped and version tokens that could not be parsed",
    )
    args = parser.parse_args()

    index, loaded, skipped, warnings, unsupported = load_ioc_index(args.repo_root)

    if not loaded:
        print(f"error: no IOC package CSVs found under {args.repo_root}", file=sys.stderr)
        return 2

    for warning in warnings:
        print(f"warning: {warning}", file=sys.stderr)

    if args.export_json:
        payload = json.dumps(export_json(index, loaded), indent=2) + "\n"
        if args.export_json == "-":
            sys.stdout.write(payload)
        else:
            Path(args.export_json).write_text(payload, encoding="utf-8", newline="\n")
            print(f"Wrote {args.export_json}")
        return 0

    if not args.lockfile:
        parser.error("a lockfile is required unless --export-json is used")

    sources = ", ".join(f"{campaign} ({count})" for _, campaign, count in loaded)
    print(f"Loaded {len(index)} packages from {len(loaded)} list(s): {sources}")

    if unsupported:
        print(
            f"Note: {len(unsupported)} version entr(ies) are ranges rather than exact "
            "pins and were not matched"
            + (" (see -v)" if not args.verbose else ":")
        )
        if args.verbose:
            for item in unsupported:
                print(f"  {item}")

    if args.verbose and skipped:
        print(f"Skipped {len(skipped)} non-package CSV(s):")
        for rel, reason in skipped:
            print(f"  {rel} ({reason})")

    installed = read_lockfile(args.lockfile)
    hits = sorted(
        (name, version, index[name][version])
        for name, version in installed
        if version in index.get(name, {})
    )

    print()
    if not hits:
        print(f"No known-malicious packages found in {args.lockfile}")
        print(f"({len(installed)} locked package(s) checked)")
        return 0

    print(f"Found {len(hits)} known-malicious package(s) in {args.lockfile}:\n")
    for name, version, campaigns in hits:
        print(f"  {name}@{version}  [{', '.join(campaigns)}]")

    return 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except BrokenPipeError:
        # Downstream closed the pipe (e.g. `| head`). Redirect stdout to
        # devnull so Python's shutdown flush does not re-raise.
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        sys.exit(1)
