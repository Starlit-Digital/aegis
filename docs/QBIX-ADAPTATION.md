# Structural proxy implementation notes

We reviewed [Qbix/proxy](https://github.com/Qbix/proxy) at commit `5a9f8a96f4bdaaaa5444b6986853e9b9724a94bc`, including its request sanitizer, HTTP and FastCGI transports, routing, statistics and deployment examples. aegis implements the useful architectural ideas independently in Go. No upstream C source is copied or linked. Qbix/proxy is MIT licensed; aegis remains under its existing 0BSD license.

The central improvement is a separate request boundary: parse constrained input, build a fresh representation, then forward to an administrator selected backend. We preserve aegis staging as a separate mode so normalization cannot weaken exact byte receipts, user binding or private storage ownership.

| Idea | aegis implementation | Reason for adaptation |
| --- | --- | --- |
| Structural request rebuilding | Strict JSON, query and URL encoded parsers, followed by regeneration | Grammar, Unicode, duplicate names and decoded limits are checked before forwarding. |
| Multipart processing before PHP | Text fields become URL encoded forms; file parts are rejected | PHP receives no multipart body through this mode. Uploads use private staging and application grants. |
| Backend routing | Longest segment prefix, explicit host/method/format allowlists, at most 16 routes | Empty lists do not mean allow everything, and `/api` does not match `/apievil`. |
| HTTP and FastCGI | Private fixed Unix sockets, no DNS or environmental proxy; one request per connection | Request values cannot select destinations, scripts, schemes, ports or trust settings. |
| FastCGI parameters | Fixed local front controller and small generated parameter set | No request path becomes a filename. No arbitrary header becomes PHP configuration. |
| Framing checks | Go HTTP parser plus singleton header validation and rejection of chunked proxy ingress | Go removes Content-Length when parsing chunked bodies, so rejecting all transfer encodings avoids forwarding a hidden framing conflict. |
| Resource budgets | Existing 1 MiB body, 2 operations and 15 second maxima; new 4 MiB response limit and bounded CGI records/stderr | Headers cannot increase limits; complete response validation precedes delivery. |
| Response hygiene | Strip hop headers, backend identification and internal file redirect headers; preserve separate cookies | Avoid leaking server details or triggering an edge internal file redirect. |
| Health and Prometheus | Optional separate loopback listener with its own key, fixed counters | No public monitoring routes, request history, user labels or secrets. |
| Deployment helpers | Read only nginx, Apache and Caddy plans, disabled example config and explicit rollback instructions | No automatic editing, reload, installation or live policy API. |
| Release transparency | CI tests and tag triggered binary builds with checksums | Release assets come from the tagged source and are independently buildable. |

We intentionally exclude public binding, request supplied FastCGI filenames, remote backends, raw access logs, recent request URI history, unrestricted header forwarding, multipart file extension trust and assertions of protection against every unknown PHP flaw. CORS, user authorization, schema validation, signed webhooks, WebSockets, streamed responses and persistent storage require their own reviewed contracts.

The tradeoffs are real. Rebuilding changes byte signatures. Strict field names exclude PHP bracket forms and repeated query keys. Multipart file clients need an explicit staging integration. Response buffering excludes large downloads and server events. A fixed front controller excludes arbitrary PHP file execution. These constraints make the trust boundary smaller, but require representative application testing before adoption.

## Acceptance and rollback

The tests must show normalized bytes at a real Unix HTTP backend, a FastCGI responder and, where installed, isolated PHP FPM. Rejected inputs must reach no backend. Configuration snapshots must be immutable. Oversize requests and responses, timeouts, header aliases, private metrics and shutdown must fail safely. Existing encrypted staging and PHP adapter tests must continue passing.

Neither example configuration is enabled. Building, testing and releasing the feature does not activate it in an application. Adoption requires reviewing the edge route, fixed socket permissions, patched PHP, cgroup limits and application compatibility. Rollback restores the saved edge configuration and stops aegis after draining; PHP patches and prior restrictions remain in place.

## Evidence limits

These are architectural reductions in exposure, not a verified remediation of the PHP CVEs. The [official PHP advisory](https://www.php.net/archive/2026.php#2026-10-21-5) and [PHP Foundation explanation](https://thephp.foundation/blog/2026/10/21/todays-php-security-release-and-how-were-strengthening-php-security/) describe OOM corruption and stale global state, including application execution paths. Only updating PHP addresses the underlying runtime defects. Local tests use synthetic traffic, not production load or exploit payloads.
