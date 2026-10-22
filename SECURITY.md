# Aegis security model

Version 0.1.0 is an early staging service, dormant by default. Report suspected vulnerabilities through the GitHub repository's private vulnerability reporting channel if available. Do not publish secrets or uploaded data in an issue.

Untrusted clients control body bytes and ordinary HTTP headers. They cannot read local config, signing keys, storage keys or the spool. The application issuer, local administrator, service user, kernel, Go runtime and reverse proxy remain trusted. A compromised issuer can authorize operations for its subjects. Local administrators and a compromised service process can access plaintext while it is being handled. Encryption of staging does not remove that trust.

The spool is dedicated, private and outside all web roots. Aegis holds an exclusive local lock. Do not run multiple instances against it or place it on an untrusted filesystem. PHP must run under a different account and must not have spool or storage key access. Do not expose the read or delete operations through a public proxy. An object ID is a selector, never authorization. Ticket grants bind audience, subject, purpose, operation, identity and expiry. The registry in the owning application binds the same identity to the current session and workflow. Tokens must not appear in URLs, analytics or logs.

Compiled ceilings and startup config own resource policy. Header claims, body metadata and ticket contents cannot raise it. Network defaults are loopback only with short deadlines and bounded admission. Go parser checks handle wire ambiguity; the application additionally rejects duplicate headers, forwarded identity, trailers, body encodings, unexpected media types and query parameters. JSON decoding rejects malformed UTF 8, lone surrogates, duplicate keys, excess nesting, large strings, token exhaustion and trailing values. The parser preserves validated byte content and does not rewrite names or identities.

The Go memory setting is soft. Linux deployment must retain the cgroup memory limit and bounded file descriptors. The reference service also restricts address families and network access. No claim is made that every kernel, runtime, filesystem or future parser vulnerability is prevented. Keep the Go runtime patched. No foreign language parser, shell or uploaded executable is invoked.

Staging is ephemeral. Rejected, expired and consumed objects are removed. Graceful shutdown drains handlers and removes its private session directory; next startup removes abandoned sessions under the spool lock. Failed retrieval is not resumable. Loss or corruption of staging requires a fresh upload. It must never be the only copy of user work.

Before enabling a future application integration, review record validation, fresh user authorization, revocation, atomic commit, import quotas and business encryption separately. Moving ingress into Go does not fix existing PHP logic or runtime vulnerabilities.
