# Development

Run `just check` before submitting a change. Keep Rust routes and the generated
OpenAPI document synchronized. Follow the service, UI, and adapter boundaries
in [ARCHITECTURE.md](ARCHITECTURE.md).

Use fictional fixtures. Never include a real host, account, key, password,
session, network map, log, or deployment export. Review both staged files and
Git history before publishing. The privacy check is a guardrail, not proof that
a source tree contains no sensitive information.

Credential transport requires separate review and tests. Do not add unlock
services to HA, general SSH command execution, implicit trust of host keys, or
automatic password retries.
