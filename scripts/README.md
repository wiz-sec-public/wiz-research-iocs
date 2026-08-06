# Scripts

Local tooling added on top of the upstream
[wiz-sec-public/wiz-research-iocs](https://github.com/wiz-sec-public/wiz-research-iocs)
data. Everything here only *reads* the upstream files, so pulling from upstream
never conflicts.

## `scan_npm_lockfile.py`

Checks an npm lockfile against the supply-chain package lists in this repo
(currently `reports/keyv-packages.csv` and `reports/shai-hulud-2-packages.csv`).

```bash
python scripts/scan_npm_lockfile.py /path/to/package-lock.json
python scripts/scan_npm_lockfile.py /path/to/pnpm-lock.yaml
```

Exits `1` if any locked package/version matches a known-malicious release, `0`
if clean — so it can gate CI.

### Staying current

There is no generated index to regenerate. The script discovers IOC data at run
time by scanning the repo for CSVs with a `Package` column, so keeping it
up to date is just:

```bash
git pull upstream main
```

Set that remote up once with:

```bash
git remote add upstream git@github.com:wiz-sec-public/wiz-research-iocs.git
```

This matters because upstream revises these lists frequently while a campaign is
live — `keyv-packages.csv` was updated three times on a single day.

New campaign CSVs are picked up with no code change, including ones using
different column names (`Version`, `Malicious Versions`, `Affected Versions`, …).
Non-package IOC files (domains, hashes, IAM names) are ignored automatically.

### Options

| Flag | Purpose |
| --- | --- |
| `-v`, `--verbose` | List skipped CSVs and version entries that could not be matched |
| `--export-json PATH` | Write the normalised package data to a file (`-` for stdout) |
| `--repo-root PATH` | Search a different checkout for IOC CSVs |

`--export-json` is generated on demand rather than committed, so it can never go
stale against upstream.

### Caveats

- Only exact version pins are matched. Range expressions (`>=1.0.0 <2.0.0`) are
  reported as unmatched rather than silently ignored — see `-v`.
- A CSV with a `Package` column but no recognisable version column raises a
  warning instead of being skipped quietly, so upstream schema changes surface.
- `pnpm-lock.yaml` parsing is a best-effort line scan of the `packages:` section
  (stdlib only, no PyYAML) and may not cover every pnpm lockfile version.
