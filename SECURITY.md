# Security Policy

cloak's entire value proposition is "your secrets never leave your machine
unredacted" - so a vulnerability here is taken seriously and handled
quickly.

## Reporting a vulnerability

Please report security issues privately, not via a public GitHub issue.

Preferred: open a [private security advisory](../../security/advisories/new)
on this repository. That path is restricted to maintainers and the
reporter, so nothing about the issue is visible publicly until it's fixed.

Please include:

- The version/commit of cloak you're running (`cloak version`).
- Steps to reproduce, or a minimal example (sanitized - don't include a
  real secret in the report).
- What you'd expect cloak to have redacted/blocked that it didn't, or any
  other way the request/response could leak data it shouldn't.

## Scope

In scope: anything that defeats the core promise - a secret or PII value
that should have been redacted from an outgoing request but wasn't, a
placeholder that gets restored into the wrong session's response (see the
session-ID handling in `internal/proxy`), the audit log recording a real
value instead of metadata, or the in-memory vault persisting to disk.

Out of scope (known, already documented in the README rather than hidden):
the generic high-entropy/PII rules are regex + checksum based, not ML, and
won't catch every possible secret shape - that's a detection-coverage
discussion, not a vulnerability report, unless it specifically breaks one
of the guarantees above.

## Response

Acknowledgment within a few days. If confirmed, a fix is prioritized ahead
of other work and the reporter is credited (if desired) once it ships.
