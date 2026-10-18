# Security boundaries

Manual password SSH is a permanent feature, independent of automatic phase
detection. Users configure a target and account, verify new or changed server
identity through normal first-connection confirmation, then enter a password
for one explicit attempt. No client-key authentication or copied phase-key
configuration is required for manual login.

This remains an experimental prerelease tested with synthetic SSH peers.
Actual Mac recovery and the deployed HTTP/proxy path need supervised validation.

## Manual SSH identity and intent

The SSH handshake verifies the server's key-exchange signature and retains the
same connection through confirmation and authentication. Certificates are
rejected. A candidate identity alone is not authorization to send a password.
New and changed identities require a distinct, authenticated confirmation action
before password entry. A changed identity is never silently accepted or
replaced. Users must verify its displayed fingerprint through a trusted source.
An explicitly provisioned normal-runtime public identity can bootstrap trust.

Only public server identities persist in owner-only /data/ssh_known_hosts.
The app uses standard known_hosts records, an append-only explicit trust step,
readback, bounded file size/identities, and regular-file/permission checks.
A new connection always checks its identity against remembered trust. Any rekey
on the retained connection must use that same selected identity. The manual
path does not require an extra pre-authentication rekey or reconnect.

The server binds the candidate connection to a random 60-second nonce, secure
session cookie, allowed HA user, exact HTTPS origin, and manual/automatic
action.
Trust confirmation checks the same binding before remembering a public identity.
It does not authenticate an account. Password submission separately requires
explicit manual intent and trusted identity, consumes the grant atomically,
and permits one password method. No automatic retry, method fallback, shell,
command, PTY, agent forwarding, or general-purpose proxy is provided.

Unknown phase, unavailable detection, and detected runtime do not prohibit an
explicit manual request to a trusted target. Accepted password authentication
reports authenticated, not FileVault-unlocked. Ambiguous disconnect reports
unconfirmed. Neither result proves desktop login or required service health.

## Password boundary

Only the user enters and submits the real password directly in the reviewed UI.
Agents, chat, screenshots, DOM/request inspectors, and browser automation must
never receive it. It must not enter options, files, commands, environment,
headers, URLs, cookies, HA entities/services/events/automations, recorder,
traces, history, notifications, or logs. No account-password configuration field
exists. The similarly masked status_token option is a different read-only
service credential, never an account password.

The dedicated ingress endpoint accepts at most 1,024 UTF-8 bytes in an
application/octet-stream body. The client clears the field before its one POST,
clears mutable buffers, and clears on expiry/cancel/navigation/page hiding.
There is no browser storage, analytics, transcript, automatic reconnect, retry,
or password cache.

The backend uses a non-cloneable, non-printable zeroizing Secret, moving its
bytes into russh's owned password method. That String is zeroized on drop and
its Debug representation is redacted. Socket shutdown on cancellation/drop
ends the library session. Passwords are not reused for status checks.
Browser, HTTP, library, swapping, and compromised-client copies cannot be
absolutely ruled out; this is best-effort handling, not guaranteed erasure.

HA/Supervisor ingress proxies transiently process the request body. Review
logging, buffering, storage, and crash behavior with dummy data before entering
a real password. Application input-bearing request logging is discarded and
responses use fixed outcome/error vocabulary. Safe configuration errors never
include user-provided values.

## Authentication and limits

Require the trusted Supervisor peer and explicitly allowed user identity for
all UI, trust, and password routes. Sidebar visibility alone is not authority.
Require exact HTTPS Origin, same-origin Fetch Metadata, no query payload,
bounded body size, nonce/session/user binding, expiry, and atomic consumption.
The read-only integration token cannot open the UI, remember identities, create
an SSH grant, or submit a password.

The controller bounds pending grants, serializes preparation, permits one
in-flight attempt, and applies 60-second startup/attempt cooldowns. Connection
and identity checks have five-second limits; authentication has a 30-second
limit. A cancelled task cannot create an automatic retry. A failed or ambiguous
attempt needs a new explicit user action after applicable limits.

## Status and optional phase classification

SSH online means a trusted cryptographic identity is reachable; it does not
prove FileVault state. Runtime identity observation does not require enabling
phase recovery or marking phase enrollment verified. A key observed during
normal runtime is not automatically exclusive to that phase.

The optional automatic profile requires independently trusted, distinct,
stable, phase-exclusive preboot/runtime identities and supervised calibration.
There is no generic banner detector or shared-key fallback. Repeated preboot
proof and a fresh retained-connection rekey gate automatic requests. A separate
pinned normal-runtime proof gates Running on that path. Invalid or incomplete
phase options show a safe error and disable suggestions while leaving the
authenticated dashboard and valid manual path available. They never fabricate
manual_enrollment_verified or rewrite target settings.

## Persistence and deployment

Approved automatic pairing creates one mode-0600 read-only integration token
in /data/credentials.json, stable across restarts, and announces it through
standard authenticated Supervisor self-info/discovery. HA confirms before
credential validation or Core config-entry storage. No owner API credential or
Mac password is generated. Include this persistence and remembered public SSH
identities in installation/update scope.

The optional Python adapter runs inside HA Core and stores the read-only token.
It exposes a fixed status sensor and no unlock service, mutation bridge, or
password-bearing attributes. Its trust boundary is separate from the app.

Before disruptive hardware testing, prove remote ingress and control survive
loss of the target Mac, establish a usable fallback, verify the exact outlet,
backup, safe shutdown/power-on procedure, and outage scope, then obtain concrete
approval. An unvalidated recovery attempt cannot be its own fallback.
User-direct
password entry and independent service checks remain required.

Publication requires source/history/private-data review, exact-head CI,
negative identity/intent/expiry/concurrency tests, native container smoke,
license checks, and explicit publication approval. Source prereleases must
state hardware limitations. Installation and hardware actions are separate.
No private vulnerability-reporting channel is configured; never post secrets
or deployment details in a public pull request.
