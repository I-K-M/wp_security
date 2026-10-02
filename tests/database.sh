#!/usr/bin/env bash
# Disposable local SQL fixture; no customer database or data is used.
set -euo pipefail
fixture="$(mktemp -d)"
trap 'rm -rf "$fixture"' EXIT
sudo apt-get update -qq
sudo apt-get install -y -qq mysql-server mysql-client
sudo systemctl start mysql
if sudo mysql --execute 'SELECT 1;' >/dev/null 2>&1; then
  admin=(sudo mysql)
elif mysql --user=root --password=root --execute 'SELECT 1;' >/dev/null 2>&1; then
  # GitHub-hosted fixture images use this published test credential.
  admin=(mysql --user=root --password=root)
else
  echo 'Cannot initialise disposable MySQL fixture' >&2
  exit 1
fi
"${admin[@]}" <<'SQL'
CREATE DATABASE wp_security_fixture;
CREATE TABLE wp_security_fixture.custom_options (option_value TEXT);
INSERT INTO wp_security_fixture.custom_options VALUES ('eval(SECRET_FIXTURE_VALUE)');
CREATE USER 'wpfixture'@'127.0.0.1' IDENTIFIED BY 'fixture-only-password';
GRANT SELECT ON wp_security_fixture.* TO 'wpfixture'@'127.0.0.1';
SQL
umask 077
cat > "$fixture/mysql.cnf" <<'CONFIG'
[client]
user=wpfixture
password=fixture-only-password
host=127.0.0.1
database=wp_security_fixture
CONFIG
mkdir "$fixture/site"
code=0
python3 local_scan.py --root "$fixture/site" --mysql-config "$fixture/mysql.cnf" --table-prefix custom_ --output "$fixture/report.json" || code=$?
[[ "$code" == 1 ]]
python3 - "$fixture/report.json" <<'PY'
import json,sys
text=open(sys.argv[1]).read()
assert 'SECRET_FIXTURE_VALUE' not in text
rows=json.loads(text)['results']
assert len(rows)==1 and rows[0]['id']=='DB-OPTIONS' and rows[0]['status']=='suspicious'
assert rows[0]['evidence'].startswith('1 option rows')
PY
if mysql --defaults-file="$fixture/mysql.cnf" --execute "DELETE FROM custom_options;" >/dev/null 2>&1; then
  echo 'SELECT-only fixture unexpectedly allowed writes' >&2
  exit 1
fi
printf 'Aggregate-only report, custom prefix, read-only account and secret redaction passed.\n'
