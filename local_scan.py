#!/usr/bin/env python3
"""Read-only offline WordPress triage. Never imports or executes site PHP."""
import argparse
import fnmatch
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import urllib.request

RULES = [
 ('LOCAL-OBFUSCATION', re.compile(rb'(?:eval|assert)\s*\(\s*(?:base64_decode|gzinflate|gzuncompress|str_rot13)\s*\(', re.I), 'high'),
 ('LOCAL-PROCESS', re.compile(rb'\b(?:shell_exec|passthru|proc_open|popen)\s*\(', re.I), 'medium'),
]

def finding(rule, path, status, severity, evidence, confidence='low'):
    return dict(id=rule, path=path, status=status, severity=severity, confidence=confidence, evidence=evidence)

def safe_open(root, relative):
    parts = Path(relative).parts
    if not parts or Path(relative).is_absolute() or '..' in parts: raise OSError('Unsafe path')
    directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in parts[:-1]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory); directory = next_fd
        return os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    finally: os.close(directory)

def scan_files(root, max_bytes, excludes):
    rows = []
    for directory, dirs, files in os.walk(root, followlinks=False, onerror=lambda e: rows.append(finding('LOCAL-READ', '', 'unknown', 'none', 'Directory unreadable'))):
        dirs[:] = sorted(d for d in dirs if not (Path(directory) / d).is_symlink() and not any(fnmatch.fnmatch((Path(directory) / d).relative_to(root).as_posix(), p) for p in excludes))
        for name in sorted(files):
            path = Path(directory) / name
            relative = path.relative_to(root).as_posix()
            if path.is_symlink() or path.suffix.lower() not in ('.php', '.phtml', '.php5', '.phar') or any(fnmatch.fnmatch(relative, p) for p in excludes):
                continue
            try:
                fd = safe_open(root, relative)
                with os.fdopen(fd, 'rb') as handle:
                    if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
                        rows.append(finding('LOCAL-READ', relative, 'unknown', 'none', 'Not a regular file')); continue
                    body = handle.read(max_bytes + 1)
                if len(body) > max_bytes:
                    rows.append(finding('LOCAL-SIZE', relative, 'unknown', 'none', 'File exceeds configured limit')); continue
                digest = hashlib.sha256(body).hexdigest()
                if relative.startswith('wp-content/uploads/'):
                    rows.append(finding('LOCAL-UPLOAD-PHP', relative, 'suspicious', 'high', 'Executable extension in uploads; SHA256 ' + digest))
                for rule, pattern, severity in RULES:
                    match = pattern.search(body)
                    if match:
                        line = body[:match.start()].count(b'\n') + 1
                        rows.append(finding(rule, relative, 'suspicious', severity, f'Pattern at line {line}; SHA256 {digest}; manual review required'))
            except OSError:
                rows.append(finding('LOCAL-READ', relative, 'unknown', 'none', 'File unreadable or changed during scan'))
    return sorted(rows, key=lambda r: (r['path'], r['id']))

def verify_inventory(root, checksums):
    rows = []
    for name, expected in sorted(checksums.items()):
        relative = Path(name)
        if relative.is_absolute() or '..' in relative.parts or not re.fullmatch(r'[a-fA-F0-9]{32}', expected):
            raise ValueError('Invalid checksum manifest')
        path = root / relative
        if any((root / Path(*relative.parts[:i])).is_symlink() for i in range(1, len(relative.parts)+1)):
            rows.append(finding('INTEGRITY-SYMLINK', name, 'unknown', 'none', 'Symlink not followed')); continue
        try:
            fd = safe_open(root, name)
            with os.fdopen(fd, 'rb') as handle:
                if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode): raise OSError('Not a regular file')
                hasher = hashlib.md5()
                for block in iter(lambda: handle.read(65536), b''): hasher.update(block)
                digest = hasher.hexdigest()
            if digest.lower() != expected.lower():
                rows.append(finding('INTEGRITY-MISMATCH', name, 'suspicious', 'high', 'Differs from reference; modifications are not automatically malware', 'high'))
        except OSError:
            rows.append(finding('INTEGRITY-MISSING', name, 'unknown', 'none', 'Reference file missing or unreadable'))
    for directory in ('wp-admin', 'wp-includes'):
        base = root / directory
        if base.is_symlink(): continue
        for folder, dirs, files in os.walk(base, followlinks=False):
            dirs[:] = [d for d in dirs if not (Path(folder)/d).is_symlink()]
            for file in files:
                relative = (Path(folder)/file).relative_to(root).as_posix()
                if relative not in checksums:
                    rows.append(finding('INTEGRITY-EXTRA', relative, 'suspicious', 'medium', 'Extra file in core directory; review manually', 'medium'))
    return rows

def official_checksums(version, locale):
    if not re.fullmatch(r'\d+\.\d+(?:\.\d+)?', version) or not re.fullmatch(r'[A-Za-z_]+', locale):
        raise ValueError('Invalid explicit WordPress version/locale')
    url = f'https://api.wordpress.org/core/checksums/1.0/?version={version}&locale={locale}'
    with urllib.request.urlopen(url, timeout=15) as response:
        data = response.read(2 * 1024 * 1024 + 1)
        if len(data) > 2 * 1024 * 1024: raise ValueError('Checksum response too large')
    checksums = json.loads(data).get('checksums')
    if not isinstance(checksums, dict) or not checksums: raise ValueError('No checksums for requested version/locale')
    return checksums

def database_checks(config, prefix):
    if not re.fullmatch(r'[A-Za-z0-9_]+', prefix): raise ValueError('Invalid table prefix')
    info = config.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_uid != os.geteuid():
        raise ValueError('MySQL config must be a regular owner-only file owned by the current user')
    # Query aggregates only. Use a dedicated SELECT-only account and a database
    # selected in the defaults file. Neither values nor user identities are emitted.
    query = f"SELECT COUNT(*) FROM `{prefix}options` WHERE option_value REGEXP 'eval[[:space:]]*\\\\(|gzinflate[[:space:]]*\\\\(';"
    process = subprocess.run(['mysql', '--defaults-file=' + str(config.resolve()), '--batch', '--skip-column-names', '--connect-timeout=5', '--execute', query], capture_output=True, timeout=30, check=False)
    if process.returncode: return [finding('DB-OPTIONS', '', 'unknown', 'none', 'Database query failed; raw output omitted')]
    value = process.stdout.strip()
    if not value.isdigit(): return [finding('DB-OPTIONS', '', 'unknown', 'none', 'Unexpected database response')]
    count = int(value)
    return [finding('DB-OPTIONS', '', 'suspicious' if count else 'pass', 'medium' if count else 'none', f'{count} option rows contain review patterns; no contents exported')]

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--output', type=Path, help='New private JSON report file')
    parser.add_argument('--max-bytes', type=int, default=4 * 1024 * 1024)
    parser.add_argument('--exclude', action='append', default=[])
    parser.add_argument('--wp-version', help='Explicit trusted core version for official checksum verification')
    parser.add_argument('--locale', default='en_US')
    parser.add_argument('--mysql-config', type=Path)
    parser.add_argument('--table-prefix', default='wp_')
    args = parser.parse_args()
    if not args.root.is_dir() or args.max_bytes <= 0: parser.error('Root must exist; max-bytes must be positive')
    root = args.root.resolve()
    rows = scan_files(root, args.max_bytes, args.exclude)
    if args.wp_version:
        try: rows.extend(verify_inventory(root, official_checksums(args.wp_version, args.locale)))
        except Exception: rows.append(finding('INTEGRITY-REFERENCE', '', 'unknown', 'none', 'Official checksums unavailable or invalid'))
    if args.mysql_config:
        try: rows.extend(database_checks(args.mysql_config, args.table_prefix))
        except Exception: rows.append(finding('DB-OPTIONS', '', 'unknown', 'none', 'Database configuration or query could not be evaluated'))
    report = dict(schema_version=1, mode='local-triage', results=rows, coverage=dict(excludes=args.exclude, core_integrity=bool(args.wp_version), database=bool(args.mysql_config)), limitations='Heuristic observations do not prove a site clean or infected; premium/custom plugin integrity requires a trusted vendor reference')
    text = json.dumps(report, indent=2) + '\n'
    if args.output:
        try:
            fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'w') as handle: handle.write(text)
        except OSError: print('Cannot create new private report', file=sys.stderr); return 3
    else: print(text, end='')
    return 3 if any(r['status'] == 'unknown' for r in rows) else 1 if any(r['status'] == 'suspicious' for r in rows) else 0

if __name__ == '__main__': sys.exit(main())
