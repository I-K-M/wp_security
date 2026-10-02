# WP Security

**WordPress security assessment tooling in Go and Bash.**

`Go` · `Bash` · `WordPress` · `HTTP` · `AppSec`

A lightweight toolkit for reviewing common WordPress attack-surface issues and suspicious local code patterns.

> For systems you own, lab environments, or assessments with explicit authorization.

---

## What it does

### Remote attack-surface checks

The Go scanner checks for common exposure patterns such as:

- `readme.html` version disclosure
- REST API user enumeration
- exposed `xmlrpc.php`
- accessible `wp-config.php`
- exposed `.env`
- exposed `.git/`
- directory listing under uploads
- missing security headers

Checks are executed concurrently and can be exported as JSON.

### Local malware-oriented inspection

The Bash scanner reviews WordPress files and database content for suspicious patterns and dangerous PHP constructs commonly associated with injected or obfuscated code.

## Usage

Build the remote scanner:

```bash
go build -o wp-pentest wp_pentest.go
```

Run it:

```bash
./wp-pentest --url https://example.com
```

Export JSON:

```bash
./wp-pentest --url https://example.com --json
```

## Example findings

```text
=== WordPress Pentest Tool v2 ===
Target: https://example.com

[-] readme.html not found
[-] REST API users protected
[+] xmlrpc.php exposed
[-] .env not accessible

=== Security Headers Check ===
[+] X-Frame-Options present
[+] Content-Security-Policy present
[-] Permissions-Policy missing
```

## Scope

This is intentionally a focused assessment toolkit, not a complete vulnerability scanner.

It is most useful for:

- WordPress hardening reviews
- lab work
- quick external exposure checks
- post-incident triage support
- validating remediation

## Authorization

Only scan systems you own or have explicit permission to assess.
