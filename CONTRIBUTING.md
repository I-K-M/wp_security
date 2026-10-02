# Contributing

Run `go test -race ./...`, `go vet ./...`, `python3 -m unittest discover -s tests -v`, `shellcheck full-wp-malware-scan-logged.sh` and `git diff --check`.

Use local httptest fixtures, never external customer targets in CI. New detection rules require a true-positive fixture, normal-content fixture, unexpected/error response fixture and evidence that secret contents do not enter reports. Keep rule IDs stable and state coverage limits explicitly.

Do not add attack payload execution, automatic deletion/quarantine or PHP bootstrapping to local incident triage. Database additions must use read-only queries and bounded, redacted outputs. Document CLI compatibility changes and unknown-result handling.
