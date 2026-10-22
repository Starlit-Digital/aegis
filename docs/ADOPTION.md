# Future adoption decision

Aegis was built and tested locally on October 22, 2026. It remains disabled and stopped. No PayCal runtime route, browser flow, autoload configuration or deployment was changed.

We can choose bounded JSON batches within the existing application, or introduce Aegis as an isolated byte receiver. Go is the selected prototype because its standard HTTP library and small deployment footprint suit a tightly constrained service. Rust remains a reasonable alternative when its operational and dependency costs fit the team. A WebSocket transport would require another lifetime, origin, admission and backpressure design; the current import workflow does not justify it. HTTP upload plus server progress is sufficient for the prototype.

Before rollout we need to select a specific workflow and schema, decide whether opaque binary support should be disabled for that instance, establish the application registry and revocation contract, and repair protected persistence and atomic commit. We should measure RSS, CPU, latency, file descriptors and disk usage under worst allowed inputs and stalled clients on the intended Linux host. Aegis has not undergone an independent production security assessment.

A pilot would use a separate unprivileged account and private spool, retain the supplied OS caps, and expose only PUT through a reviewed proxy. Keep the current application path behind an explicit feature decision. Rollback stops Aegis, removes its proxy route and abandons ephemeral stages; it does not alter committed business data. Do not enable the example unit or configuration as part of publishing this repository.
