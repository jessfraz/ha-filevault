# Architecture

The service follows Maintenance and Shipments: Rust 2024, Dropshot, typed
OpenAPI, embedded HTML/CSS/JavaScript, HA ingress, an unprivileged container,
and a thin Python coordinator. Reused public MIT source retains its notice.

## Request flow

`GET /v1/status` accepts a read-only bearer credential or an allowlisted HA
user arriving from the configured Supervisor peer. Static UI requests require
ingress authorization. The HA adapter exposes one fixed enum status sensor
and registers no unlock entity, service, mutation bridge, or automation.

The UI offers Unlock only for fresh, repeated, identity-bound preboot proof
and a transport that explicitly supports recovery. Normal runtime,
unreachable, unknown, booting, and contradictory evidence hide the control.
The default transport is disabled. The optional real SSH probe performs a
pinned key exchange, rejects certificates, and always reports unknown.
Neither production transport can submit a password.

`POST /v1/session` requires the trusted ingress peer, allowed user, exact HTTPS
origin, same-origin Fetch Metadata, and an empty body. The controller obtains
two matching verified-preboot observations, then retains the second connection
for a grant valid for at most 60 seconds. The response contains a random
single-use nonce and a separate Secure, HttpOnly, SameSite=Strict session
cookie.
Pending grants are bounded in memory; a timer discards expired grants and
retained connections. Concurrent preparation requests are rejected.

`POST /v1/unlock` accepts at most 1,024 UTF-8 bytes in an octet-stream body.
No target, account, command, or protocol choice comes from the browser. The
server checks the ingress context, nonce, session, user, origin, expiry, and
attempt limits, atomically consumes the grant, and rechecks identity and
preboot state on the retained connection before invoking the transport once.
Positive runtime proof or a timeout checking for contradictory runtime evidence
rejects preparation and submission.

The controller allows one in-flight attempt per target, a 60-second startup
and attempt cooldown, five-second connection/recheck limits, a 30-second
submission limit, and up to 120 seconds for separate runtime confirmation.
Cancellation leaves admission blocked until process restart; it cannot create
an automatic retry. Submission completion or SSH closure alone never means
running. Without positive runtime proof, the result is booting or unknown.

## Temporary credential handling

The masked field exists only in the dedicated UI. The client clears it before
the request, clears its mutable byte buffer, and clears the form on expiry,
cancellation, navigation, or page hiding. There is no browser storage,
analytics, transcript, retry, or password-bearing HA entity/service path.

The backend wraps credential bytes in a non-cloneable, non-printable,
zeroizing type. They are consumed by one transport call and dropped before
runtime polling. The type currently exposes only a constant-time comparison
for synthetic test transports. Real SSH authentication is absent. HTTP
framework and browser copies exist transiently; zeroization cannot guarantee
erasure of every copy, swap page, or compromised client.

Application request logging is discarded and responses use a fixed outcome
vocabulary. HA and Supervisor ingress proxies still process request bodies.
Their buffering, logs, and crash behavior require deployment review with
dummy data before any real credential is entered.

## Reference differences

| Reference pattern | FileVault decision |
| --- | --- |
| SQLite domain state and migrations | No database or durable attempt history |
| Generated owner/integration credentials | No credential generation or automatic pairing |
| HA action services and mutation bridge | Read-only status adapter; recovery uses dedicated ingress |
| Embedded dashboard and relative paths | Reused with a masked ephemeral dialog |
| Mutation-intent header | Also require origin, session, nonce, expiry, and server-side proof |
| Structured request logger | Discard input-bearing request logs |
| Tagged multiarch releases | Same structure, with publication gated pending readiness review |

## Unimplemented production boundaries

A supervised verification must establish preboot host identity and a reviewed
preboot-specific detector. An open SSH port, version banner, absent service,
or pinned key alone is insufficient. The runtime identity check and exact
Apple authentication conversation also remain unimplemented. Synthetic test
transports are defined only in test code and cannot be enabled by app options.
