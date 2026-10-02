# WP Security

**Evidence-based WordPress exposure checks and read-only local triage.**

[![Security CI](https://github.com/I-K-M/wp_security/actions/workflows/security.yml/badge.svg)](https://github.com/I-K-M/wp_security/actions/workflows/security.yml)

Two focused tools: a Go HTTP scanner for an authorised origin, and a local Python scanner that never executes site PHP. Both preserve incomplete observations and omit secret contents from reports.

## Remote assessment

Requires Go 1.24+ to build; CI uses a pinned Go compiler. Tagged releases provide standalone binaries.

```bash
go build -o wp-security ./cmd/wp-security
./wp-security --url https://YOUR_AUTHORISED_SITE
./wp-security --url https://YOUR_AUTHORISED_SITE --format json --output report.json
```

The former `go build wp_pentest.go` entry point has moved to `cmd/wp-security`. `--json` remains an alias, but JSON now goes to stdout; it no longer silently creates `report.json`.

Requests are GET-only, same-origin redirects are bounded, response bodies default to 1 MiB and request starts are paced. Configure `--timeout`, `--max-bytes`, `--workers`, `--rate` and `--fail-on medium|high|critical`. The initial request rate excludes automatic redirects; each request can follow at most three redirects within the same origin. WordPress installations in a subdirectory are supported by the base URL path.

| Check | Required evidence |
|---|---|
| PHP configuration disclosure | PHP source plus database configuration markers |
| Environment disclosure | Environment/secret assignment syntax, not just HTTP 200 |
| Git metadata | Valid `.git/HEAD` format |
| Upload indexing | Index title plus links |
| Author visibility / XML-RPC | Informational exposure; not automatically an exploit |
| Readme | WordPress documentation markers |
| Headers | Case-insensitive retrieval and basic value checks; not a full CSP assessment |

A nonexistent control path detects common fallback pages. Identical fallback responses, response-limit failures, timeouts, forbidden redirects and server failures remain `unknown`. Non-matching evidence means only that this check observed no matching exposure, not that the site is secure. WAFs and dynamic fallback pages may still affect results.

## Local triage

Requires Python 3.10+ on Linux/macOS. Scan a read-only snapshot when investigating a compromised site.

```bash
python3 local_scan.py --root /path/to/wordpress --output local-report.json
python3 local_scan.py --root /path/to/wordpress --wp-version 6.8.3 --locale en_US
bash full-wp-malware-scan-logged.sh --root /path/to/wordpress
```

Use the actual trusted core version, not the illustrative value above. Explicit core verification retrieves the official WordPress checksum inventory over HTTPS. No WordPress bootstrap, plugin loading or PHP execution is performed. Hash differences are integrity findings, not automatic malware verdicts. Add repeatable `--plugin slug@trusted-version` options to verify WordPress.org plugins against official SHA256 inventories. Missing references remain unknown; premium/custom plugin integrity requires a trusted vendor reference and is outside this verifier.

The file scanner walks once, skips symlinks, limits file reads and reports contextual obfuscation/process patterns and executable extensions in uploads. Results contain relative paths, line numbers and SHA256 hashes, never code excerpts. Use repeatable `--exclude PATTERN` options for reviewed exclusions; exclusions are recorded in report coverage.

Optional database inspection uses a dedicated SELECT-only account in an owner-only MySQL defaults file:

```bash
python3 local_scan.py --root /path/to/wordpress \
  --mysql-config /private/mysql-audit.cnf --table-prefix custom_
```

The file must be owned by the invoking account with no group/other permissions, and select the intended database. Credentials are never supplied as command-line passwords. The query exports aggregate counts only; raw SQL results, user identities and error contents are omitted. It is heuristic coverage, not a complete database malware scan.

## Report and exit contract

Reports use schema version `1`, stable rule IDs, severity, confidence and evidence. Remote output is ordered deterministically. New report files have mode 0600 and never overwrite an existing file or symlink.

| Exit | Meaning |
|---|---|
| 0 | No finding at the configured threshold; evaluated checks complete |
| 1 | Remote threshold met, or local suspicious evidence needs review |
| 2 | Invalid CLI request |
| 3 | Incomplete assessment or report-write failure; takes precedence over findings |

CI automation must retain reports on codes 1 and 3. Local `suspicious` results never claim that malware is confirmed. A clean heuristic result never proves the site clean.

## Verification and delivery

CI runs local HTTP fixtures, Go race tests, `go vet`, govulncheck, Python tests, ShellCheck and source secret/configuration scanning. Tests contact no external assessment target. Release builds cover Linux amd64/arm64, Windows amd64 and macOS arm64; cross-compilation is not a claim that every host was runtime-tested.

See [delivery verification](docs/delivery.md), [threat model](docs/threat-model.md), [contributing](CONTRIBUTING.md) and [security reporting](SECURITY.md). Use only on systems you own or have explicit permission to assess.
