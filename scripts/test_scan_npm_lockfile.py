import json
import subprocess
import sys

import pytest

from scan_npm_lockfile import (
    REPO_ROOT,
    find_hits,
    load_ioc_index,
    parse_package_lock,
    parse_pnpm_lock,
    parse_versions,
    split_pnpm_key,
)

SCRIPT = REPO_ROOT / "scripts" / "scan_npm_lockfile.py"


@pytest.mark.parametrize(
    "cell, expected",
    [
        ("1.1.7, 1.1.8", ["1.1.7", "1.1.8"]),
        ("= 0.0.7 || = 0.0.8", ["0.0.7", "0.0.8"]),
        ("6.0.0", ["6.0.0"]),
        ("= 1.4.2511142126", ["1.4.2511142126"]),
    ],
)
def test_parse_versions_exact(cell, expected):
    assert parse_versions(cell)[0] == expected


@pytest.mark.parametrize(
    "token",
    [
        ">=1.0.0 <2.0.0",  # comparator
        "1.x",  # wildcard, and \w would match the x
        "2.X",
        "latest",  # dist-tag
        "v1.2.3",  # git-tag style; no lockfile writes a v prefix
    ],
)
def test_parse_versions_reports_anything_not_an_exact_pin(token):
    """These can never equal a locked version, so they must be reported, not indexed."""
    exact, unchecked = parse_versions(token)
    assert exact == []
    assert unchecked == [token]


@pytest.mark.parametrize(
    "key, expected",
    [
        ("keyv@4.5.4", ("keyv", "4.5.4")),  # v9
        ("@adobe/css-tools@4.5.0", ("@adobe/css-tools", "4.5.0")),  # v9 scoped
        ("/keyv@4.5.4", ("keyv", "4.5.4")),  # v6
        ("/@scope/name@1.2.3", ("@scope/name", "1.2.3")),  # v6 scoped
        ("/lodash/4.17.21", ("lodash", "4.17.21")),  # v5
        ("/@scope/name/1.2.3", ("@scope/name", "1.2.3")),  # v5 scoped
        ("@ai-sdk/azure@0.0.10(zod@3.25.76)", ("@ai-sdk/azure", "0.0.10")),  # v9 peer
        ("/react-dom/16.8.0_react@16.8.0", ("react-dom", "16.8.0")),  # v5 peer
        ("/@babel/core/7.0.0_@babel+helper@7.0.0", ("@babel/core", "7.0.0")),
        ("some_pkg@1.0.0", ("some_pkg", "1.0.0")),  # underscore in the name itself
        ("@scope/name", (None, None)),  # no version
        ("lodash@github.com/lodash/lodash#4.17.21", (None, None)),  # git
        ("some-pkg@catalog:default", (None, None)),  # pnpm catalog
    ],
)
def test_split_pnpm_key(key, expected):
    assert split_pnpm_key(key) == expected


def test_parse_package_lock_v3_flat_packages(tmp_path):
    lockfile = tmp_path / "package-lock.json"
    lockfile.write_text(
        json.dumps(
            {
                "lockfileVersion": 3,
                "packages": {
                    "": {"name": "root", "version": "1.0.0"},
                    "packages/my-workspace-lib": {"version": "9.9.9"},
                    "node_modules/my-workspace-lib": {
                        "resolved": "packages/my-workspace-lib",
                        "link": True,
                    },
                    "node_modules/keyv": {"version": "4.5.4"},
                    "node_modules/@cacheable/memory": {"version": "2.2.1"},
                    "node_modules/a/node_modules/nested": {"version": "1.0.0"},
                },
            }
        ),
        encoding="utf-8",
    )

    found, unparsed = parse_package_lock(lockfile)

    assert found == {
        ("keyv", "4.5.4"),
        ("@cacheable/memory", "2.2.1"),
        ("nested", "1.0.0"),
    }
    assert unparsed == []


def test_parse_package_lock_v3_resolves_alias_to_the_real_package(tmp_path):
    """npm puts the real package in "name" and the alias in the path."""
    lockfile = tmp_path / "package-lock.json"
    lockfile.write_text(
        json.dumps(
            {
                "lockfileVersion": 3,
                "packages": {
                    "node_modules/safe-looking-name": {
                        "name": "keyv",
                        "version": "6.0.0",
                    }
                },
            }
        ),
        encoding="utf-8",
    )

    found, _ = parse_package_lock(lockfile)

    assert found == {("keyv", "6.0.0")}


def test_parse_package_lock_v1_nested_dependencies(tmp_path):
    lockfile = tmp_path / "package-lock.json"
    lockfile.write_text(
        json.dumps(
            {
                "lockfileVersion": 1,
                "dependencies": {
                    "express": {
                        "version": "4.19.2",
                        "dependencies": {"cacheable": {"version": "2.5.1"}},
                    }
                },
            }
        ),
        encoding="utf-8",
    )

    found, _ = parse_package_lock(lockfile)

    assert found == {("express", "4.19.2"), ("cacheable", "2.5.1")}


def test_parse_package_lock_v1_resolves_npm_alias_versions(tmp_path):
    lockfile = tmp_path / "package-lock.json"
    lockfile.write_text(
        json.dumps(
            {
                "lockfileVersion": 1,
                "dependencies": {"safe-looking-name": {"version": "npm:keyv@6.0.0"}},
            }
        ),
        encoding="utf-8",
    )

    found, _ = parse_package_lock(lockfile)

    assert found == {("keyv", "6.0.0")}


def test_parse_pnpm_lock_reads_packages_and_ignores_snapshots(tmp_path):
    lockfile = tmp_path / "pnpm-lock.yaml"
    lockfile.write_text(
        "lockfileVersion: '9.0'\n"
        "packages:\n"
        "  keyv@4.5.4:\n"
        "    resolution: {integrity: sha512-fake==}\n"
        "  '@adobe/css-tools@4.5.0':\n"
        "    resolution: {integrity: sha512-fake==}\n"
        "snapshots:\n"
        "  keyv@4.5.4: {}\n"
        "  should-not-appear@1.0.0: {}\n",
        encoding="utf-8",
    )

    found, unparsed = parse_pnpm_lock(lockfile)

    assert found == {("keyv", "4.5.4"), ("@adobe/css-tools", "4.5.0")}
    assert unparsed == []


def test_parse_pnpm_lock_reports_keys_it_cannot_resolve(tmp_path):
    """Git and catalog entries are not registry installs and cannot be checked."""
    lockfile = tmp_path / "pnpm-lock.yaml"
    lockfile.write_text(
        "packages:\n"
        "  keyv@4.5.4: {}\n"
        "  'lodash@github.com/lodash/lodash#4.17.21': {}\n",
        encoding="utf-8",
    )

    found, unparsed = parse_pnpm_lock(lockfile)

    assert found == {("keyv", "4.5.4")}
    assert unparsed == ["lodash@github.com/lodash/lodash#4.17.21"]


def write_csv(directory, name, text):
    (directory / name).write_text(text, encoding="utf-8")


def test_load_ioc_index_uses_filename_as_campaign_and_ignores_other_ioc_types(tmp_path):
    write_csv(tmp_path, "campaign-a.csv", "Package,Version\nkeyv,= 6.0.0\n")
    write_csv(
        tmp_path, "campaign-b.csv", 'Package,Affected Versions\nkeyv,"6.0.0, 7.0.0"\n'
    )
    write_csv(tmp_path, "domains.csv", "Type,Value\nDomain,evil[.]com\n")

    iocs = load_ioc_index(tmp_path)

    assert iocs.index["keyv"]["6.0.0"] == ["campaign-a", "campaign-b"]
    assert iocs.index["keyv"]["7.0.0"] == ["campaign-b"]
    assert iocs.sources == [("campaign-a", 1), ("campaign-b", 1)]
    assert iocs.warnings == []


def test_load_ioc_index_accepts_a_package_column_name_variant(tmp_path):
    """A campaign CSV must not vanish because its header is not exactly 'Package'."""
    write_csv(tmp_path, "campaign.csv", "Package Name,Malicious Versions\nkeyv,6.0.0\n")

    iocs = load_ioc_index(tmp_path)

    assert iocs.index["keyv"]["6.0.0"] == ["campaign"]
    assert iocs.warnings == []


@pytest.mark.parametrize(
    "header, expected_warning",
    [
        ("Package,Notes", "no version column"),
        ("Component,Version", "no package column"),
        ("Package,Version Added,Version Fixed", "ambiguous version columns"),
    ],
)
def test_load_ioc_index_warns_instead_of_skipping_unusable_package_csvs(
    tmp_path, header, expected_warning
):
    write_csv(tmp_path, "campaign.csv", f"{header}\nkeyv,1.0.0,2.0.0\n")

    iocs = load_ioc_index(tmp_path)

    assert iocs.sources == []
    assert len(iocs.warnings) == 1
    assert expected_warning in iocs.warnings[0]


def test_load_ioc_index_prefers_a_known_version_column_over_column_order(tmp_path):
    """Indexing 'Last Safe Version' would flag safe installs and miss malicious ones."""
    write_csv(
        tmp_path,
        "campaign.csv",
        "Package,Last Safe Version,Malicious Versions\nkeyv,4.5.4,6.0.0\n",
    )

    iocs = load_ioc_index(tmp_path)

    assert iocs.index == {"keyv": {"6.0.0": ["campaign"]}}
    assert iocs.warnings == []


def test_load_ioc_index_reports_rows_it_cannot_index(tmp_path):
    write_csv(
        tmp_path,
        "campaign.csv",
        "Package,Version\nno-version-pkg,\nranged-pkg,>=1.0.0\nfine,1.0.0\n",
    )

    iocs = load_ioc_index(tmp_path)

    assert iocs.index == {"fine": {"1.0.0": ["campaign"]}}
    assert len(iocs.unchecked) == 2
    assert any("no-version-pkg has no version" in u for u in iocs.unchecked)
    assert any("ranged-pkg >=1.0.0" in u for u in iocs.unchecked)


def test_load_ioc_index_discards_a_csv_it_could_not_finish_reading(tmp_path):
    """A mid-file read error must not leave a partial campaign in the index."""
    good = "Package,Version\n" + "".join(f"pkg-{i},1.0.0\n" for i in range(50))
    (tmp_path / "campaign.csv").write_bytes(good.encode("utf-8") + b"bad-row,\xff\xfe\n")

    iocs = load_ioc_index(tmp_path)

    assert iocs.index == {}
    assert iocs.sources == []
    assert len(iocs.warnings) == 1
    assert "could not be read" in iocs.warnings[0]


def test_find_hits_matches_exact_version_only():
    index = {"keyv": {"6.0.0": ["keyv-packages"]}}

    assert find_hits(index, {("keyv", "4.5.4")}) == []
    assert find_hits(index, {("keyv", "6.0.0")}) == [
        ("keyv", "6.0.0", ["keyv-packages"])
    ]


def first_ioc_row():
    """A real (package, version) pair from this repo's CSVs."""
    iocs = load_ioc_index(REPO_ROOT)
    name = sorted(iocs.index)[0]
    return name, sorted(iocs.index[name])[0]


def run_scan(lockfile):
    return subprocess.run(
        [sys.executable, str(SCRIPT), str(lockfile)],
        capture_output=True,
        text=True,
    )


def test_scan_exits_1_and_names_a_package_listed_in_the_repo_csvs(tmp_path):
    """End to end: real CSV data indexed, matched, reported, exit 1."""
    name, version = first_ioc_row()
    lockfile = tmp_path / "package-lock.json"
    lockfile.write_text(
        json.dumps(
            {
                "lockfileVersion": 3,
                "packages": {f"node_modules/{name}": {"version": version}},
            }
        ),
        encoding="utf-8",
    )

    result = run_scan(lockfile)

    assert result.returncode == 1
    assert f"{name}@{version}" in result.stdout


def test_scan_exits_0_on_a_clean_lockfile(tmp_path):
    lockfile = tmp_path / "package-lock.json"
    lockfile.write_text(
        json.dumps(
            {
                "lockfileVersion": 3,
                "packages": {"node_modules/express": {"version": "4.19.2"}},
            }
        ),
        encoding="utf-8",
    )

    result = run_scan(lockfile)

    assert result.returncode == 0
    assert "No known-malicious packages found." in result.stdout


@pytest.mark.parametrize(
    "filename, content",
    [
        ("yarn.lock", ""),  # unsupported name
        ("package-lock.json", "[]"),  # valid JSON, wrong shape
        ("package-lock.json", "{}"),  # parses to zero packages
        ("pnpm-lock.yaml", "just a scalar"),  # valid YAML, wrong shape
    ],
)
def test_scan_exits_2_rather_than_reporting_clean_or_matched(tmp_path, filename, content):
    """No verdict is far better than a wrong one; 1 would read as 'malicious found'."""
    lockfile = tmp_path / filename
    lockfile.write_text(content, encoding="utf-8")

    result = run_scan(lockfile)

    assert result.returncode == 2
    assert "no verdict" in result.stderr


def test_repo_csvs_still_parse():
    """Asserts no warnings, and that both shipped campaigns are still indexed."""
    iocs = load_ioc_index(REPO_ROOT)
    counts = dict(iocs.sources)

    assert iocs.warnings == []
    assert {"keyv-packages", "shai-hulud-2-packages"} <= counts.keys()
    assert counts["keyv-packages"] >= 443
    assert counts["shai-hulud-2-packages"] >= 795
