# Architecture

Rust/Dropshot serves an embedded UI through HA ingress, with an optional
read-only Python coordinator. The stack, automatic pairing, light/dark palette,
and packaging follow Maintenance and Shipments; reused MIT notices remain.

## Two explicit SSH actions

The permanent manual action configures host/port/username, verifies a fresh
SSH server handshake, and retains that cryptographic connection. A known_hosts
store classifies the identity as trusted, new, or changed. Candidates are pinned
for any rekey but cannot receive a password until separately confirmed.

POST /v1/manual/session creates a user/session/origin-bound 60-second grant and
returns account, fingerprint, and trust state to authenticated ingress only.
POST /v1/manual/trust requires explicit identity confirmation and remembers
only the public server identity after checking that same live connection.
POST /v1/manual/attempt separately requires trusted identity and manual intent,
consumes the grant, and sends one SSH password request. No phase assertion,
client key, shell, command, PTY, fallback method, or automatic retry is
involved.
Authenticated and unconfirmed are honest results, not unlock-success claims.

The optional automatic profile uses distinct, manually calibrated phase keys.
POST /v1/session repeats preboot observations and retains the connection.
POST /v1/unlock rechecks identity/phase through a fresh key exchange and sends
one password request. Only separate pinned runtime proof produces Running;
a disconnect alone remains booting/unknown. Both actions share attempt limits,
concurrency control, session binding, and ephemeral password handling. Grants
cannot change action type.

## Status and configuration

GET /v1/system gives fixed role/capability and safe configuration metadata
without network probes or credentials. GET /v1/status reports calibrated phase
proof when available, otherwise trusted SSH reachability without authentication.
SSH online is distinct from proved normal runtime/FileVault state. Manual action
availability does not depend on the phase request completing successfully.

Invalid SSH profile values become fixed, redacted configuration errors while
the authenticated dashboard remains available and that action stays disabled.
Existing options are not rewritten. A blank manual target can reuse the existing
legacy target; saved normal-runtime public identity can bootstrap host trust.
No password field exists in target configuration.

## Credential and persistence boundaries

Passwords travel only as bounded octet-stream bodies on dedicated ingress
routes, never URLs, headers, logs, options, HA entities/services/events,
recorder,
or traces. UI buffers and fields clear before/after one POST and on
cancellation,
expiry, or navigation. Rust Secret is zeroizing and non-printable; russh's owned
password method is zeroized on drop. Socket shutdown closes cancelled attempts.
These are best-effort memory boundaries; browser/proxy/library copies exist.

The app stores a read-only pairing token in mode-0600 credentials.json and
public server identities in mode-0600 ssh_known_hosts under managed /data.
Supervisor receives only the read-only token/internal origin via discovery.
Core confirmation precedes token probing/storage. The token cannot access UI,
trust, session, or password routes. No owner mutation API credential is needed.

HA ingress requires the configured Supervisor peer, explicit user allowlist,
exact HTTPS Origin, same-origin Fetch Metadata, secure cookie, random single-use
nonce, action binding, expiry, bounded payload, and one in-flight attempt.
Operational errors are fixed strings; input-bearing request logging is
discarded.
Dummy-data deployment review must establish proxy logging/buffering behavior.

## Distribution

Native amd64/arm64 app images use /data, initial ownership setup then UID 10001,
ingress 8099, and optional internal read-only 8080 with host mapping disabled.
No privileged/host-network/device/mount/Core-API/broad-Supervisor grant is
needed.
The optional HACS custom-repository adapter executes inside Core and exposes
one fixed enum sensor. It is not default-catalog listed.

App and integration brand PNGs are byte-identical at 256 and 512 pixels; release
packaging checks both copies and dimensions. Standard sidebar metadata uses the
matching Material Design vault icon. Source/integration archives include only
committed public source, with provenance/checksums. Tag/image publication
follows
exact-head CI and explicit approval. Deployment and hardware tests are separate.
