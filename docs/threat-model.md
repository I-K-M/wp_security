# Threat model and diagnostic limits

The HTTP target and local WordPress files are untrusted input. The scanner limits decoded response size, per-request time and parallelism, refuses redirects outside the initial scheme/host/port and omits response bodies from findings. Invalid targets with credentials, fragments or queries are rejected.

The remote scanner may intentionally reach private lab addresses. It is an operator CLI, not a hosted service accepting arbitrary public URLs; adding a public API would require a separate SSRF policy. GET endpoints may still have server-side effects; authorisation remains necessary.

HTTP status alone never establishes a secret leak. A baseline endpoint reduces soft-404 false positives, but a WAF can hide evidence and dynamic pages can defeat equality checks. Unknown outcomes are retained, not silently treated as safe. Header observations are basic checks, not complete policy analysis.

Local triage reads files through no-follow descriptors and never executes PHP. Reports omit source text and secret values; relative paths and hashes can still be sensitive. Database queries use a separately supplied private configuration and should run with SELECT-only rights. Explicit core checksums are a trusted version reference, not a malware detector or a plugin integrity guarantee.

Assessment reports are operator-controlled artifacts and should not be committed or uploaded unredacted. CI fixtures contain synthetic data only. Repository-owned code has no selected distribution license yet; bundled third-party systems retain their own policies.
