# Verification

Run `make verify`, `make compile`, `./build/aegis selftest`, and `python3 scripts/smoke.py`.

Unit tests cover exact encrypted round trips and receipts, ownership, upload replay across restarts and concurrent replay, single use reads, corrupted ciphertext, private spool ownership, crash cleanup, subject and global staging quotas, global rate admission, malformed UTF 8, split multibyte sequences, duplicate keys, Unicode escape pairs, parser depth, token and string limits, malformed and trailing JSON, oversized bodies with and without a declared length, headers trying to raise limits, unexpected content encodings, multipart rejection, origin rejection, duplicate authorization, forged and expired grants, invalid config, disabled startup and key permissions. Race detection checks the concurrent state transitions.

The selftest creates an actual loopback HTTP server with temporary keys. The smoke test launches the built process, obtains an upload grant from the PHP adapter, streams Unicode JSON to Aegis, verifies the digest, consumes it through PHP, checks a stalled upload deadline, then stops the process and checks staging removal and closed listener. It prints no tickets or keys.

Screenshots are generated from captured command output in the established macOS terminal frame. They are rendered transcripts, not claims that production is enabled. `docs/screenshots/*.txt` preserves the actual output used in the images.

Linux CI runs the unit and PHP interoperability tests. Local Linux cross compilation additionally checks portability. Neither validates cgroup enforcement. Linux service limits need validation on the deployment host before adoption. No live production load, denial of service or exploit test is part of this repository's local verification.

## Structural proxy verification

Run `python3 scripts/proxy-smoke.py` after compiling. It creates a private Unix HTTP backend, an actual Aegis child process and a separate authenticated monitoring listener. If `php-fpm` is on PATH, it additionally starts an isolated foreground PHP FPM pool with its own temporary configuration, Unix socket and synthetic front controller. It never changes the installed PHP configuration or existing workers. The script tests rebuilt Unicode JSON and exact large numbers, canonical forms, fixed CGI metadata, rejected duplicate keys and PHP override headers, route boundaries, private metrics, a stalled upload deadline and both listener closures. Temporary fixtures and processes are removed on exit.

Go tests additionally exercise both transports, invalid paths and PHP field aliases, multipart conversion and file rejection, response limits before disclosure, preserved cookies, stripped file redirect headers, invalid CGI output, raw HTTP framing conflicts, actual chunked input rejection, immutable configuration and compiled ceilings. The FastCGI tests use Go's independent standard responder. Passing these tests does not establish safety for arbitrary PHP applications or prove the PHP CVEs are repaired.

The 0.2.0 local verification used PHP 8.5.12 in the isolated FPM pool. A short form normalization fuzz run completed 115,457 executions without a failure. Fuzzing is supplementary evidence and does not establish exhaustive coverage. The standard checks include race detection and Go vet.
