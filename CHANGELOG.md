# Changes

## 0.2.1

* Use lowercase aegis consistently across the CLI, documentation, PHP reference names, assets and release metadata.

## 0.2.0

* Add opt in structural proxy mode, inspired by Qbix/proxy and implemented independently in Go.
* Add strict request rebuilding for JSON, forms and multipart text fields, with explicit host, method, format and segment route allowlists.
* Add fixed Unix HTTP and FastCGI backends, bounded response validation and header filtering.
* Add a separate authenticated monitoring listener and read only web server integration plans.
* Add synthetic transport tests and isolated PHP FPM process verification.
* Expand the README with use cases, setup, examples, compatibility, rollback, contribution guidance and official PHP security references.
* Preserve encrypted staging and disabled example configurations.

## 0.1.0, October 22, 2026

Initial prototype. Adds immutable local policy with compiled ceilings, operation and purpose bound grants, measured streaming byte limits, strict multibyte JSON validation, encrypted private staging, replay protection across restarts, bounded admission and retention, and single use retrieval. Includes a reference PHP adapter, macOS verification, Linux cross compilation, deployment reference, security model and captured terminal test images. Building and testing do not activate a deployment.
