# WP Post-Hack Scanner

A bash script I personally use during **WordPress post-hack clean-up and investigations**.  
It helps detect suspicious PHP code patterns and inspects the database for potential malicious payloads.

---

## What This Script Does

 **Scans PHP files** for known suspicious functions often used in malware or obfuscated code:

- `eval(`
- `base64_decode(`
- `gzinflate(`
- `gzuncompress(`
- `str_rot13(`
- `shell_exec(`
- `exec(`
- `passthru(`
- `system(`
- `assert(`
- `preg_replace(`
- `create_function(`
- `file_put_contents(`
- `curl_exec(`
- `popen(`
- `proc_open(`
- `fopen(`
- `php_uname(`

---

 **Scans these WordPress directories**:

- `wp-content/cache`
- `wp-content/uploads`
- `wp-content/plugins`
- `wp-content/themes`
- `wp-content/mu-plugins`
- `wp-includes`
- the current directory (`.`)

---

 **Runs SQL queries** against your WordPress database to:

- detect suspicious base64 payloads in `wp_options`
- look for `<script>` tags inside post content
- inspect cron jobs
- check transients for potential malware
- list the largest autoloaded options
- dump user accounts
- check user capabilities

All results are saved into a log file: `scan-result.log`.

---

## How to Use

**1. Edit database credentials** at the bottom of the script:


DB_NAME='your_db_name'

DB_USER='your_db_user'

DB_PASS='your_db_password'

DB_HOST='localhost'

**2. Make the script executable:**

chmod +x wp-posthack-scan.sh

**3. Run the script:**

./wp-posthack-scan.sh
 

**Output**
All output is logged into scan-result.log for later review.

Alerts are highlighted in red if suspicious patterns are found.

⚠️ Disclaimer
This script does not clean or remove infected files automatically, it only detects suspicious content & you have to check manually afterwards.

Always back up your site and database before running any scripts.

**Why I Use It**
In my work maintaining WordPress sites, after a hack I need to quickly spot suspicious code or database payloads that may persist even after cleaning infected files.
This script saves time by scanning systematically for known malicious patterns.

Happy scanning, and stay safe!
