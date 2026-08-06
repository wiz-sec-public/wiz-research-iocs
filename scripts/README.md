# scripts

## scan_npm_lockfile.py

Checks an npm or pnpm lockfile against the malicious-package CSVs in this repo.

### Usage

```bash
pip install -r scripts/requirements.txt
python scripts/scan_npm_lockfile.py path/to/package-lock.json
python scripts/scan_npm_lockfile.py path/to/pnpm-lock.yaml
```

Exit codes: `0` no match, `1` at least one match, `2` usage or data error.

Output on a match:

```
IOC lists: keyv-packages (443), shai-hulud-2-packages (795)
Lockfile: 1727 packages

1 known-malicious package(s):
  keyv@6.0.0  [keyv-packages]
```

### Supported lockfiles

| File | Formats |
| --- | --- |
| `package-lock.json` | lockfileVersion 1, 2, 3 |
| `pnpm-lock.yaml` | v5 (`/name/1.2.3`), v6 (`/name@1.2.3`), v9 (`name@1.2.3`) keys |

Workspace entries in `package-lock.json` and the `snapshots:` section of
`pnpm-lock.yaml` are skipped; both duplicate or shadow registry installs.

### IOC data

CSVs are read at run time. Every CSV in the repo with a `Package` column is
indexed and the filename stem is used as the campaign name, so adding a
campaign CSV requires no code change. CSVs without a `Package` column
(domains, hashes, wallets) are ignored.

Matching is on exact versions. Two cases are reported on stderr rather than
passed over silently:

- a version cell holding a range instead of a pin — it cannot be compared to a
  locked version, so it is not matched
- a CSV with a `Package` column but no recognisable version column

### Tests

```bash
pip install -r scripts/requirements.txt pytest
pytest scripts
```

`test_repo_csvs_still_parse` runs against the repo's own CSVs and fails if a
future CSV cannot be indexed. CI runs the suite on changes to `scripts/` or to
any CSV.
