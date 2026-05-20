# ctscan

Personal CLI for scanning Certificate Transparency logs. Fetches entries from the tail of a CT log, parses X.509 with `cryptography` (including precerts via `extra_data`), supports SQL-like queries, Python filter expressions, JSON rules, and DNS enrichment. Matches are stored in SQLite; export to CSV or save PEM files.

## Requirements

- Python **≥ 3.11**
- Network access to the target CT log (e.g. `ct.googleapis.com`, `ct.cloudflare.com`). The log list is fetched from `gstatic.com` (with cache/builtin fallback on failure).

## Install

```bash
cd /path/to/ctscan
python3.11 -m venv .venv    # optional, recommended
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e .
ctscan --help
```

## Commands

| Command | Description |
|---------|-------------|
| `ctscan logs` | List CT logs (`--refresh` updates online list and cache) |
| `ctscan scan` | Scan and write to SQLite |
| `ctscan jobs` | List scan jobs and hit counts |
| `ctscan status` | Active job and total hits in DB |
| `ctscan export` | Export hits to CSV |
| `ctscan save-certs` | Backfill PEM files for hits in DB |
| `ctscan purge` | Delete jobs/hits (pick one mode) |
| `ctscan data-dir` | Print default data directory |

---

## Typical workflow

### 1. Scan with a fixed log and filter

```bash
ctscan scan \
  --log-uri "https://ct.googleapis.com/logs/us1/argon2026h1/" \
  --filter "issuer_org == \"Let's Encrypt\"" \
  --target 10
```

### 2. Interactive log selection (`--pick`)

```bash
ctscan scan --pick \
  --filter "issuer_org == \"Let's Encrypt\"" \
  --target 3 \
  --batch-size 20 \
  --verbose
```

Three prompts: **year → operator → log** (enter a number; Enter defaults to `1`).

- List source may be `live`, `disk_cache` (`~/.ctscan/cache/`), or `builtin`; a message is shown.
- **Operator** is the CT log **operator** (Google, Cloudflare, …), not the certificate issuer. Filter LE certs with `--query` / `--filter` regardless of operator.
- Prefer logs marked **✓** and `usable`. **Unknown** at the top often means missing year in cache; prefer **2026/2027**.
- For Google Argon: year **2026** → operator **Google** → **Argon2026h1**.

### 3. Inspect jobs and export

Each `scan` creates a row in `scan_jobs` (unless resuming a `running` job). Hits live in `matches`, deduplicated by `(job_id, domain)`.

```bash
ctscan jobs
ctscan status

# Default: latest completed job only
ctscan export -o latest.csv

# Specific job (see ID in ctscan jobs)
ctscan export -o job2.csv --job-id 2

# All hits across all jobs
ctscan export -o everything.csv --all
```

**Example:** one scan with `--target 10`, then `--pick --target 3`:

- `ctscan export -o out.csv` → **3 rows** (latest completed job only)
- `ctscan export -o ten.csv --job-id <first-job-id>` → 10 rows
- `ctscan export -o all.csv --all` → 13 rows (if nothing was purged)

### 4. Save certificate PEM

```bash
ctscan scan --log-uri "https://ct.googleapis.com/logs/us1/argon2026h1/" \
  --filter "issuer_org == \"Let's Encrypt\"" --target 5 --save-cert

ctscan save-certs
ctscan save-certs --job-id 3 --certs-dir ./my-certs
```

### 5. Purge data

`purge` requires exactly one of: `--job-id`, `--all`, `--completed`. Confirmation prompt unless `--yes`.

```bash
ctscan purge --job-id 2 --yes
ctscan purge --completed --yes   # completed jobs only; keeps running
ctscan purge --all --yes         # wipe database
```

---

## `scan` options

| Option | Description |
|--------|-------------|
| `--log-uri` | CT log base URL |
| `--pick` | Interactive log picker (mutually exclusive with `--log-uri`) |
| `--query`, `-q` | SQL-like filter (see below) |
| `--filter`, `-f` | Python expression (**mutually exclusive** with `-q`) |
| `--rules`, `-r` | JSON rules file (can combine with `-q`/`-f`) |
| `--nxdomain` | Keep only NXDOMAIN names |
| `--target`, `-n` | Stop after N hits (default 100) |
| `--batch-size` | Entries per `get-entries` request (default 50) |
| `--delay` | Seconds between batches (default 0.1) |
| `--after-date` | Keep certs with `not_before >=` string |
| `--save-cert` | Write PEM to `~/.ctscan/certs/` |
| `--no-resume` | Always create a new job (do not resume `running`) |
| `--verbose`, `-v` | Per-batch stats |
| `--proxy` | Explicit proxy URL |
| `--use-env-proxy` | Use `HTTP_PROXY`/`HTTPS_PROXY` (default: direct, no env proxy) |
| `--db` | Custom SQLite path |

**Resume:** same `log_uri` + existing `running` job → continue from `next_end_index`. Different log or `--no-resume` → new job.

---

## Filtering and rules

### SQL (`--query`)

In the shell, use **`Let''s Encrypt`** (doubled single quote = one apostrophe). Do not write `Lets Encrypt`.

| Example | Meaning |
|---------|---------|
| `issuer_org = 'Let''s Encrypt'` | Issuer organization |
| `domain LIKE '%.test'` | Domain pattern |
| `issuer_country IN ('CN', 'US')` | Country |
| `is_nxdomain(domain) = true` | NXDOMAIN |
| `is_expired = true` | Expired |
| `issuer_org = 'DigiCert' AND domain LIKE '%.cn'` | Combined |

| Operator | Meaning |
|----------|---------|
| `=`, `!=` | Equal / not equal |
| `LIKE`, `NOT LIKE` | `%` any, `_` one char |
| `IN`, `NOT IN` | List |
| `IS NULL`, `IS NOT NULL` | Null |
| `AND`, `OR`, `NOT` | Logic |

### Python filter (`--filter`)

```bash
ctscan scan --log-uri "https://ct.googleapis.com/logs/us1/argon2026h1/" \
  --filter "issuer_org == \"Let's Encrypt\" and endswith(domain, '.test')"
```

### JSON rules (`--rules`)

```bash
ctscan scan --log-uri "https://ct.googleapis.com/logs/us1/argon2026h1/" \
  --rules rules.example.json --target 50
```

Each rule has `name` and `filter` (Python). Multiple rules are OR’d; first match wins.

### Rule context fields

| Field | Description |
|-------|-------------|
| `domain` | SAN name being evaluated |
| `issuer_org`, `issuer_cn`, `issuer_country` | Issuer |
| `subject_cn`, `subject_org`, `subject_country` | Subject |
| `not_before`, `not_after` | Validity strings |
| `is_expired` | Boolean |
| `san`, `domains` | SAN list |
| `log_index` | CT index |

### Built-in functions

**DNS:** `dns_rcode`, `dns_status`, `dns_flags`, `dns_has_flag`, `dns_info`, `is_nxdomain`, `dns_exists`, `is_dnssec_secure`, `is_dnssec_insecure`

**Strings:** `matches`, `endswith`, `contains`

---

## CSV export columns

| Column | Meaning |
|--------|---------|
| `index` | Row number |
| `job_id` | `scan_jobs.id` |
| `log_index` | CT index |
| `domain` | Matched name |
| `issuer_cn`, `issuer_org` | Issuer |
| `not_before`, `not_after` | Validity |
| `matched_rule` | Rule name or query label |

---

## Data directory

Default: `~/.ctscan/` (`ctscan data-dir`)

| Path | Contents |
|------|----------|
| `ctscan.db` | SQLite (`scan_jobs`, `matches`) |
| `cache/all_logs_list.json` | Log list cache |
| `certs/{log_index}.pem` | PEM from `--save-cert` / `save-certs` |

Use `--db` on `scan`, `export`, `jobs`, etc. for a custom database path.

---

## Network and `--pick` list

### CT log connection errors (SSL / ConnectError)

`UNEXPECTED_EOF` with `http_proxy` in the stack usually means **HTTP_PROXY/HTTPS_PROXY** breaks TLS to Google.

Default: **direct** (ignore env proxy).

```bash
unset HTTPS_PROXY HTTP_PROXY ALL_PROXY https_proxy http_proxy all_proxy
ctscan scan --log-uri "https://ct.googleapis.com/logs/us1/argon2026h1/" ...
```

If you need a proxy:

```bash
ctscan scan --log-uri "..." --proxy "http://127.0.0.1:7890"
# or
ctscan scan ... --use-env-proxy
```

### Log list fetch failures

URL: `https://www.gstatic.com/ct/log_list/v3/all_logs_list.json`

Fallback: **online** → **disk cache** → **builtin list** → **type URL manually**.

```bash
ctscan logs --refresh
ctscan scan --log-uri "https://ct.googleapis.com/logs/us1/argon2026h1/" ...
```

---

## Scan feels stuck?

- Scans from the **log tail** backward. First `get-entries` can take **tens of seconds to minutes** on large logs.
- HTTP read timeout ~**180s**.
- `--verbose` prints per-batch stats.
- `--no-resume` forces a new job.
- Larger `--batch-size` (e.g. 200) fewer round trips, bigger responses.
- **Precerts:** cert DER is often in `extra_data`; “unparsed entries” in stats are real parse failures.

---

## Layout

```
src/ctscan/
  cli.py
  ct/           # HTTP client, entry parse, log list
  dns/
  rules/
  storage/
  pipeline/scanner.py
```

---

## Development

```bash
cd /path/to/ctscan
source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

## License

Copyright (C) 2026 mr-m0nst3r

This program is free software: you can redistribute it and/or modify it under the terms of the [GNU General Public License v3.0](LICENSE) (GPL-3.0-or-later), or at your option, any later version published by the Free Software Foundation.

See [LICENSE](LICENSE) for the full license text.
