# Deployment planning

aegis is an active open source project with separate structural proxy and encrypted staging modes. Building or installing the CLI does not activate an application integration. Both example configurations require an explicit local activation decision.

## Choose the boundary

Use proxy mode to rebuild JSON, forms and multipart text fields before a fixed Unix HTTP backend or PHP front controller. Use staging mode for authorized JSON or opaque binary uploads into a private encrypted spool. Use separate processes and accounts for the two modes so the proxy account cannot read staging keys or files.

Go provides the standard HTTP library and a small deployment footprint. A WebSocket transport would require a separate lifetime, origin, admission and backpressure design. The current service uses bounded HTTP requests and does not support WebSockets or streamed responses.

## Qualify an integration

Select the workflow and schema, configure narrow host, route, method and format allowlists, and verify compatibility with real application traffic. For staging, establish the application registry, revocation contract, fresh authorization, protected persistence and atomic commit. Choose JSON or opaque binary locally for each staging instance.

Measure RSS, CPU, latency, file descriptors and disk usage under worst allowed inputs and stalled clients on the intended Linux host. Retain the supplied OS caps, patch PHP and restart its workers. aegis has not undergone an independent production security assessment.

## Pilot and rollback

A staging pilot uses a separate unprivileged account and private spool, and exposes only PUT through a reviewed TLS route. Retrieval stays local. A proxy pilot uses a fixed private backend socket and a separately authorized monitoring listener if needed. Keep a copy of the previous edge configuration, validate changes before reload, and test authenticated and rejected requests.

Rollback restores the saved edge route and stops aegis after requests drain. Abandon ephemeral staging without altering committed business data. Publishing the repository, downloading a release or running the test suite does not activate a deployment.
