import json

import pytest

from scan_npm_lockfile import (
    REPO_ROOT,
    find_hits,
    load_ioc_index,
    parse_package_lock,
    parse_pnpm_lock,
    parse_versions,
    read_lockfile,
    split_pnpm_key,
)


@pytest.mark.parametrize(
    "cell, expected",
    [
        ("1.1.7, 1.1.8", ["1.1.7", "1.1.8"]),
        ("= 0.0.7 || = 0.0.8", ["0.0.7", "0.0.8"]),
        ("6.0.0", ["6.0.0"]),
        ("= 1.4.2511142126", ["1.4.2511142126"]),
        ("1.0.0-beta.1", ["1.0.0-beta.1"]),
        ("", []),
    ],
)
def test_parse_versions_exact(cell, expected):
    assert parse_versions(cell)[0] == expected


def test_parse_versions_reports_ranges_instead_of_dropping_them():
    exact, unpinned = parse_versions(">=1.0.0 <2.0.0, 1.2.3")
    assert exact == ["1.2.3"]
    assert unpinned == [">=1.0.0 <2.0.0"]


@pytest.mark.parametrize(
    "key, expected",
    [
        ("keyv@4.5.4", ("keyv", "4.5.4")),  # v9
        ("@adobe/css-tools@4.5.0", ("@adobe/css-tools", "4.5.0")),  # v9 scoped
        ("/keyv@4.5.4", ("keyv", "4.5.4")),  # v6
        ("/@scope/name@1.2.3", ("@scope/name", "1.2.3")),  # v6 scoped
        ("/lodash/4.17.21", ("lodash", "4.17.21")),  # v5
        ("/@scope/name/1.2.3", ("@scope/name", "1.2.3")),  # v5 scoped
        ("@ai-sdk/azure@0.0.10(zod@3.25.76)", ("@ai-sdk/azure", "0.0.10")),  # peer suffix
        ("@scope/name", (None, None)),  # no version
        ("", (None, None)),
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
                    "node_modules/keyv": {"version": "4.5.4"},
                    "node_modules/@cacheable/memory": {"version": "2.2.1"},
                    "node_modules/a/node_modules/nested": {"version": "1.0.0"},
                },
            }
        ),
        encoding="utf-8",
    )

    found = parse_package_lock(lockfile)

    assert found == {
        ("keyv", "4.5.4"),
        ("@cacheable/memory", "2.2.1"),
        ("nested", "1.0.0"),
    }


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

    assert parse_package_lock(lockfile) == {
        ("express", "4.19.2"),
        ("cacheable", "2.5.1"),
    }


def test_parse_pnpm_lock_reads_packages_and_ignores_snapshots(tmp_path):
    lockfile = tmp_path / "pnpm-lock.yaml"
    lockfile.write_text(
        "lockfileVersion: '9.0'\n"
        "importers:\n"
        "  .:\n"
        "    dependencies:\n"
        "      keyv:\n"
        "        specifier: ^4.5.4\n"
        "        version: 4.5.4\n"
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

    assert parse_pnpm_lock(lockfile) == {
        ("keyv", "4.5.4"),
        ("@adobe/css-tools", "4.5.0"),
    }


def test_read_lockfile_rejects_unknown_filename(tmp_path):
    other = tmp_path / "yarn.lock"
    other.write_text("", encoding="utf-8")

    with pytest.raises(ValueError, match="unsupported lockfile"):
        read_lockfile(other)


def write_csv(directory, name, text):
    path = directory / name
    path.write_text(text, encoding="utf-8")
    return path


def test_load_ioc_index_uses_filename_as_campaign_and_ignores_other_ioc_types(tmp_path):
    write_csv(tmp_path, "campaign-a.csv", "Package,Version\nkeyv,= 6.0.0\n")
    write_csv(
        tmp_path, "campaign-b.csv", 'Package,Affected Versions\nkeyv,"6.0.0, 7.0.0"\n'
    )
    write_csv(tmp_path, "domains.csv", "Type,Value\nDomain,evil[.]com\n")

    iocs = load_ioc_index(tmp_path)

    assert iocs.index["keyv"]["6.0.0"] == ["campaign-a", "campaign-b"]
    assert iocs.index["keyv"]["7.0.0"] == ["campaign-b"]
    assert [campaign for _, campaign, _ in iocs.sources] == ["campaign-a", "campaign-b"]
    assert iocs.warnings == []


def test_load_ioc_index_warns_when_version_column_is_missing(tmp_path):
    write_csv(tmp_path, "broken.csv", "Package,Notes\nmystery,no versions here\n")

    iocs = load_ioc_index(tmp_path)

    assert iocs.sources == []
    assert len(iocs.warnings) == 1
    assert "no version column" in iocs.warnings[0]


def test_find_hits_matches_exact_version_only():
    index = {"keyv": {"6.0.0": ["keyv-packages"]}}

    assert find_hits(index, {("keyv", "4.5.4")}) == []
    assert find_hits(index, {("keyv", "6.0.0")}) == [
        ("keyv", "6.0.0", ["keyv-packages"])
    ]


def test_repo_csvs_still_parse():
    """Guards against schema drift in the CSVs this repo ships."""
    iocs = load_ioc_index(REPO_ROOT)

    assert iocs.warnings == []
    assert len(iocs.sources) >= 1
    assert len(iocs.index) > 100
