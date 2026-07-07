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
| `ctscan operators` | List CT operators and contact emails from the log list |
| `ctscan scan` | Scan and write to SQLite |
| `ctscan jobs` | List scan jobs and hit counts |
| `ctscan status` | Active job and total hits in DB |
| `ctscan export` | Export hits to CSV |
| `ctscan save-certs` | Backfill PEM files for hits in DB |
| `ctscan dump-entries` | Download raw `ct/v1/get-entries` JSON (no cert parsing) |
| `ctscan parse-dump` | Parse a dump JSONL and extract timestamp + leaf cert fields |
| `ctscan purge` | Delete jobs/hits (pick one mode) |
| `ctscan data-dir` | Print default data directory |
| `ctscan check-br` | BR audit: DNS names must use PSL ICANN DOMAINS (not PRIVATE) |
| `ctscan roots` | List accepted root CAs from `ct/v1/get-roots` |
| `ctscan check-root` | Check which CT logs include your root CA |
| `ctscan scts` | Match certificate embedded SCTs to CT operators / logs |

---

## Typical workflow

### 1. Scan with a time interval (auto-select logs)

Match CT logs whose **`temporal_interval`** overlaps your range (from `all_logs_list.json`), then scan in parallel **by CT operator** until `--target` **unique domains** are reached:

```bash
ctscan scan \
  --from 2026-01-01 --to 2026-06-30 \
  --query "issuer_cn = 'CFCA TLS EV OCA'" \
  --target 20
```

By default one worker runs per **operator** (Google, Cloudflare, DigiCert, …); each worker scans that operator's logs sequentially. Cap parallel operators with `--concurrency 2`. Duplicate domains across logs/operators count once toward `--target`. Re-running the same interval + query resumes the session and skips logs already completed in that session.

Only **`usable`** logs are included by default; add `--include-all-states` to widen. Omit `--to` to use today; omit `--from` to search from 2013-01-01.

### 2. Scan with a fixed log and filter

```bash
ctscan scan \
  --log-uri "https://ct.googleapis.com/logs/us1/argon2026h1/" \
  --filter "issuer_org == \"Let's Encrypt\"" \
  --target 10
```

### 3. Interactive log selection (`--pick`)

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
- Prefer logs in **`usable`** state. **`unknown`** often means the log list entry has no `state` field; prefer **2026/2027** logs when scanning.
- For Google Argon: year **2026** → operator **Google** → **Argon2026h1**.

### 4. Inspect jobs and export

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

### 5. Save certificate PEM

```bash
ctscan scan --log-uri "https://ct.googleapis.com/logs/us1/argon2026h1/" \
  --filter "issuer_org == \"Let's Encrypt\"" --target 5 --save-cert

ctscan save-certs
ctscan save-certs --job-id 3 --certs-dir ./my-certs
```

### 6. Purge data

`purge` requires exactly one of: `--job-id`, `--all`, `--completed`. Confirmation prompt unless `--yes`.

```bash
ctscan purge --job-id 2 --yes
ctscan purge --completed --yes   # completed jobs only; keeps running
ctscan purge --all --yes         # wipe database
```

---

## Raw CT entries (`dump-entries` / `parse-dump`)

If you want to do your own offline analysis, you can download raw `ct/v1/get-entries`
responses **without parsing certificates**, then post-process the dump locally.

### Download a range (print head, then prompt for start/end)

```bash
ctscan dump-entries \
  --log-uri "https://ct.googleapis.com/logs/us1/argon2026h1/" \
  -o argon.jsonl
```

The first line of the output file is metadata; subsequent lines are per-entry objects:

```json
{"type":"ctscan_dump_entries", ...}
{"index":123,"entry":{"leaf_input":"...","extra_data":"..."}}
...
```

### Download a fixed range (script-friendly)

```bash
ctscan dump-entries \
  --log-uri "https://ct.googleapis.com/logs/us1/argon2026h1/" \
  --start 1000000 --end 1001999 \
  --batch-size 200 \
  -o argon_1000000_1001999.jsonl
```

### Parse the dump to JSONL/CSV (timestamp + leaf certificate fields)

```bash
# JSONL rows
ctscan parse-dump -i argon.jsonl -o parsed.jsonl

# CSV rows
ctscan parse-dump -i argon.jsonl --csv parsed.csv
```

Each parsed row includes:

- `timestamp_ms`, `timestamp_utc` (CT log entry timestamp)
- `issuer_cn`, `issuer_org`, `subject_cn`, `subject_org`
- `not_before`, `not_after`
- `domain` (first SAN) and `san` (all SANs; CSV uses `;` separator)
- `cert_der_b64` (leaf certificate DER, base64)

### Export leaf certificate DER files

```bash
ctscan parse-dump -i argon.jsonl --export-der-dir ./ders
openssl x509 -inform DER -in ./ders/123.der -noout -text
```

## `scan` options

| Option | Description |
|--------|-------------|
| `--log-uri` | CT log base URL (mutually exclusive with `--pick` and `--from`/`--to`) |
| `--pick` | Interactive log picker (mutually exclusive with `--log-uri` and `--from`/`--to`) |
| `--from` | Interval start `YYYY-MM-DD`; auto-select overlapping CT logs |
| `--to` | Interval end `YYYY-MM-DD` (inclusive); default today when `--from` is set |
| `--concurrency`, `-j` | Max parallel CT operators for interval scan (default: all operators) |
| `--refresh` | Refresh log list before resolving `--from`/`--to` |
| `--usable-only` / `--include-all-states` | When using `--from`/`--to`, default skips non-usable logs |
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

**Resume:** single-log scans resume by `log_uri`. Interval scans create a **session** (matched by `--from`, `--to`, and query); unique domains across all session jobs count toward `--target`. Per-log checkpoints resume within the session; completed logs are skipped on re-run. Use `--no-resume` to start a fresh session.

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

**PSL / BR:** `is_br_icann_psl_domain(domain)`, `psl_public_suffix(domain)`, `psl_section(domain)`

---

## BR ICANN PSL domain check

CA/Browser Forum audits often require that certificate **DNS names** are valid on the public Internet using the [Mozilla Public Suffix List](https://publicsuffix.org/list/public_suffix_list.dat). Names whose **public suffix** is listed under **PRIVATE DOMAINS** (e.g. `blogspot.com`, `github.io`, many `*.amazonaws.com` patterns) are flagged — they are not ordinary ICANN registry suffixes.

The list is cached at `~/.ctscan/cache/public_suffix_list.dat` (same official URL as above).

### Check one or more names

```bash
ctscan check-br -d www.example.com
ctscan check-br -d foo.blogspot.com    # FAIL — private suffix blogspot.com
```

### Check a certificate PEM

```bash
ctscan check-br --pem ./leaf.pem
```

### Check a CT log entry

```bash
ctscan check-br \
  --log-uri "https://ct.googleapis.com/logs/us1/argon2026h1/" \
  --log-index 12345678
```

### During scan (drop non-compliant certs)

```bash
ctscan scan --log-uri "..." \
  --filter "issuer_org == \"Let's Encrypt\"" \
  --require-br-icann \
  --target 20
```

### As a filter expression

```bash
ctscan scan --log-uri "..." --filter "is_br_icann_psl_domain(domain)" --target 10
```

This checks each SAN name being evaluated; use `--require-br-icann` to require **all** DNS names on the certificate to pass.

---

## CT log accepted roots (`get-roots`)

Each CT log publishes the set of **trusted root CAs** it accepts via [RFC 6962](https://datatracker.ietf.org/doc/html/rfc6962) `GET .../ct/v1/get-roots`. Use this to see which logs already include your root and which do not.

### Check your root across all logs

Provide your root CA via **exactly one** of `--pem`, `--der`, or `--fingerprint`:

```bash
ctscan check-root --pem /path/to/your-root.pem
ctscan check-root --der /path/to/your-root.der
ctscan check-root --fingerprint "AA:BB:CC:..."   # SHA-256, colons optional
```

By default only **usable** logs from the cached log list are checked. Include retired / other states:

```bash
ctscan check-root --pem ./root.pem --include-all-states
```

Print only logs that are **missing** your root:

```bash
ctscan check-root --pem ./root.pem --missing-only
```

Refresh the online log list before checking:

```bash
ctscan check-root --pem ./root.pem --refresh
```

Show operator contact emails (from log list ``operators[].email``) for each log and in the missing summary:

```bash
ctscan check-root --pem ./root.pem --missing-only --show-contacts
```

List all operators and emails:

```bash
ctscan operators
ctscan operators --refresh
```

Show contacts inline when listing logs:

```bash
ctscan logs --contacts
```

**Output:** a table with `Has root` = `yes` / `no` / `error`, plus a summary list of logs where your root is absent. Exit code **1** if any usable log is missing your root (handy for scripts).

### List roots from one log

```bash
ctscan roots --log-uri "https://ct.googleapis.com/logs/us1/argon2026h1/"
```

### List roots from every log in the log list

```bash
ctscan roots --all-logs
```

### `check-root` / `roots` options

| Option | Description |
|--------|-------------|
| `--pem` | Your root CA certificate (PEM) |
| `--der` | Your root CA certificate (DER) |
| `--fingerprint` | SHA-256 fingerprint of your root (hex) |
| `--usable-only` / `--include-all-states` | Filter by log list state (default: usable only) |
| `--missing-only` | `check-root` only: hide logs that already have your root |
| `--show-contacts` | `check-root` only: add operator email column from log list |
| `--refresh` | Refresh `all_logs_list.json` from gstatic before querying |
| `--delay` | Seconds between `get-roots` requests (default 0.05) |
| `--verbose`, `-v` | Print one line per log as each `get-roots` completes |
| `--proxy` | Explicit proxy URL |
| `--use-env-proxy` | Use `HTTP_PROXY`/`HTTPS_PROXY` (default: direct) |

Matching compares the full certificate DER (or SHA-256 fingerprint when `--fingerprint` is used).

**Progress:** when checking more than one log, a progress bar shows the current log (`[3/35] Google Argon2026h1 …`). A startup line reports how many logs will be queried. Each `get-roots` uses a **45s read timeout** (not the 180s scan timeout), so unreachable logs fail faster. Use `--verbose` to stream per-log results while the bar runs.

---

## Certificate embedded SCTs (`scts`)

Leaf certificates often carry **Signed Certificate Timestamps** in the X.509 extension `1.3.6.1.4.1.11129.2.4.2` (precert or embedded SCT list). Each SCT contains a `log_id` that identifies the CT log; ctscan matches it against Google's [log list](https://www.gstatic.com/ct/log_list/v3/all_logs_list.json) (classic and tiled logs).

```bash
ctscan scts --pem ./leaf.pem
ctscan scts --pem ./leaf.pem --show-contacts
ctscan scts --pem ./leaf.pem --refresh
```

**Output:** for each embedded SCT:

| Field | Meaning |
|-------|---------|
| SCT time | Timestamp when the log signed the SCT |
| Operator | CT log operator from the log list |
| Log | Log description (e.g. Google Argon2026h1) |
| State | `usable`, `rejected`, `pending`, … |
| State since | When the log entered that state |
| Period | Log `temporal_interval` (start ~ end) |
| Kind | `classic` (RFC 6962) or `tiled` |
| URL | Log URL or tiled submission/monitoring URL |

Log IDs are listed below the table. Exit code **1** if no SCTs are present or any `log_id` is not found in the cached log list.

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
| `cache/public_suffix_list.dat` | Mozilla PSL (ICANN vs PRIVATE sections) |
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
  ct/           # HTTP client, entry parse, log list, get-roots
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
