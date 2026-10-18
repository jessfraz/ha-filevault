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
The default transport is disabled. The optional handshake-only SSH probe reports
unknown. The recovery profile classifies phase only from its manually verified,
exclusive phase identities and rejects certificates.
The optional manually enrolled recovery profile supports password
authentication.
It requires independently verified, distinct phase keys and explicit enablement;
it is disabled by default and has no banner-based detector.

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
runtime polling. The adapter moves these bytes into russh's password method,
whose owned String
is zeroized on drop. Socket shutdown on drop/cancellation ends the library
session; no password is reused for runtime checks. HTTP
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
| Generated owner/integration credentials | One owner-only persistent read-only integration credential; no owner/unlock API credential |
| HA action services and mutation bridge | Read-only status adapter; recovery uses dedicated ingress |
| Embedded dashboard and relative paths | Reused with a masked ephemeral dialog |
| Mutation-intent header | Also require origin, session, nonce, expiry, and server-side proof |
| Structured request logger | Discard input-bearing request logs |
| Tagged multiarch releases | Same structure, with publication gated pending readiness review |

## Supervised hardware gate

There is no universal preboot detector. Supervised calibration must establish
that this Mac and OS offer independently trusted, distinct, phase-exclusive
host keys, that pre-authentication rekey/password authentication work, and that
the expected disconnect leads to the normal runtime identity. Shared phase
keys cannot enable this profile. Recalibrate after OS or identity changes.

`SshRecovery` performs the real SSH password method and fresh pinned runtime
handshakes; its tests use in-memory keys and loopback SSH servers, not a Mac.
Authentication failures have no method fallback or retry. Ambiguous disconnects
may await runtime proof but never imply success themselves. Normal SSH identity
is the status boundary; individual application health needs separate checks.

The HA app uses a versioned GHCR image, explicit private options, authenticated
ingress, and an optional bearer status listener internal to the app network.
Host port mapping defaults off. The Python adapter pairs explicitly and is
read-only. Automatic pairing uses the same authenticated Supervisor discovery
and HA confirmation path as the references. Only an app-owned read-only token
is generated/persisted; no Mac password is involved, and no probe or Core entry
write occurs before the pairing confirmation. Standalone setup stays explicit.
