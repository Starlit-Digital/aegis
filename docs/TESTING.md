# Verification

Run `make verify`, `make compile`, `./build/aegis selftest`, and `python3 scripts/smoke.py`.

Unit tests cover exact encrypted round trips and receipts, ownership, upload replay across restarts and concurrent replay, single use reads, corrupted ciphertext, private spool ownership, crash cleanup, subject and global staging quotas, global rate admission, malformed UTF 8, split multibyte sequences, duplicate keys, Unicode escape pairs, parser depth, token and string limits, malformed and trailing JSON, oversized bodies with and without a declared length, headers trying to raise limits, unexpected content encodings, multipart rejection, origin rejection, duplicate authorization, forged and expired grants, invalid config, disabled startup and key permissions. Race detection checks the concurrent state transitions.

The selftest creates an actual loopback HTTP server with temporary keys. The smoke test launches the built process, obtains an upload grant from the PHP adapter, streams Unicode JSON to Aegis, verifies the digest, consumes it through PHP, checks a stalled upload deadline, then stops the process and checks staging removal and closed listener. It prints no tickets or keys.

Screenshots are generated from captured command output in the established macOS terminal frame. They are rendered transcripts, not claims that production is enabled. `docs/screenshots/*.txt` preserves the actual output used in the images.

Linux cross compilation checks portability, not runtime behavior or cgroup enforcement. Linux service limits need validation on the deployment host before adoption. No live production load, denial of service or exploit test is part of this repository's local verification.
