# scripts

## scan_npm_lockfile.py

Checks an npm or pnpm lockfile against the malicious-package CSVs in this repo.

### Usage

```bash
pip install -r scripts/requirements.txt
python scripts/scan_npm_lockfile.py path/to/package-lock.json
python scripts/scan_npm_lockfile.py path/to/pnpm-lock.yaml
```

```
IOC lists: keyv-packages (443), shai-hulud-2-packages (795)
Lockfile: 1724 packages
No known-malicious packages found.
```

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | no match |
| `1` | at least one match |
| `2` | no verdict — the scan could not be completed |

Anything that makes the check incomplete is a `2`: an IOC CSV that cannot be
read or indexed, an unreadable or unrecognised lockfile, or a lockfile that
parses to zero packages. A partial scan is never reported as `0`.

### Supported lockfiles

Dispatch is on the exact filename; `npm-shrinkwrap.json` and renamed copies are
rejected.

| File | Formats |
| --- | --- |
| `package-lock.json` | lockfileVersion 1, 2, 3 |
| `pnpm-lock.yaml` | v5 (`/name/1.2.3`), v6 (`/name@1.2.3`), v9 (`name@1.2.3`) keys |

Peer suffixes are stripped in both forms pnpm has used: `(react@18.2.0)` in
v6/v9 and `_react@18.2.0` in v5.

Alias installs are resolved to the real package: npm records it under `name` in
lockfileVersion 2/3, and as `npm:name@1.2.3` in the version field in v1.

Skipped: the root project (key `""`), workspace members and their `node_modules`
symlinks (`"link": true`) in `package-lock.json`; the `snapshots:` section of
`pnpm-lock.yaml`, which repeats `packages:` keyed by peer context.

pnpm keys that do not resolve to a registry name and version — git, tarball and
`catalog:` entries — are counted and listed on stderr. They are not checked
against the IOC lists.

### IOC data

CSVs are read at run time. Any CSV in the repo with a package column is indexed,
using the filename stem as the campaign name. CSVs with neither a package nor a
version column are other IOC types (domains, hashes, wallets) and are ignored.

Column selection:

- package: a column named exactly `Package`, otherwise the first containing
  `package`
- version: a column named exactly one of `Version`, `Versions`,
  `Malicious Version(s)`, `Affected Version(s)`, otherwise the first containing
  `version`

Matching is on exact versions. Reported on stderr:

- version cells that are not exact pins (ranges, wildcards, dist-tags) — they
  cannot be compared to a locked version
- rows with a package name but no version, or a version but no package name

Reported on stderr and exit `2`, because the campaign would otherwise be
silently missing:

- a CSV with a package column but no version column, or the reverse
- a CSV with more than one candidate version column, where picking the wrong one
  could flag safe versions and miss malicious ones
- a CSV that cannot be read, including one that fails part-way through; its rows
  are discarded rather than left partially indexed

### Tests

```bash
pip install -r scripts/requirements.txt pytest
pytest scripts
```

`test_repo_csvs_still_parse` asserts that this repo's CSVs produce no warnings
and that both shipped campaigns are still indexed at their current size, so a
header change that drops a campaign fails the build. CI runs the suite on
changes to `scripts/`, to any CSV, or to the workflow.
