# Security boundaries

## Read-only HA extensions

Assist tools query the existing bounded status cache with no arguments.
Entity exposure, active-user read permission and entry ownership are rechecked
on each call. Unloaded entries, failed polls and stale/future observations fail
closed. Neither tool calls a service, sends credentials, starts SSH or changes
state. Unknown backend fields and raw message contents are discarded.

Native diagnostics construct an allowlist instead of copying entry data and
redacting known keys. Connection identities, messages, exceptions, credentials
and unknown future fields are omitted. HA adds standard environment metadata
outside this integration payload.

Notification blueprints read an explicitly selected status entity and supply
no recovery, password or power action. The action selector is for the user's
notification actions. Ambiguous status never proves locked.

Manual password SSH is a permanent feature, independent of automatic phase
detection. Users configure a target and account, verify new or changed server
identity through normal first-connection confirmation, then enter a password
for one explicit attempt. No client-key authentication or copied phase-key
configuration is required for manual login.

Manual SSH recovery has been validated through repeated supervised Mac unlocks,
in addition to synthetic SSH tests. New Mac and HTTP/proxy deployments still
need supervised validation; this does not establish universal compatibility.

## Native CLI boundary

The independent `ha-filevault` client keeps integration reads separate from
HA-authenticated recovery. Its `system` and `status` commands use fixed GET
routes for external
`/v1/system` and `/v1/status`. It sends a separately configured native
integration credential, never an HA user identity, ingress origin, cookie,
nonce, or password. Those integration credentials cannot authorize recovery.

Integration credentials come only from an explicitly selected owner-only regular token
file. The CLI has no token-value argument, automatic credential discovery, or
server environment fallback. Credential-file buffers are zeroized best-effort;
HTTP library/header copies cannot be guaranteed erased. HTTPS verifies normal
certificates. HTTP requires an already trusted network, with no implicit network
or host mapping grants. Ambient HTTP proxies are disabled.

Each integration read makes one request with redirects and retries disabled. Fixed stderr
errors never include URLs, file paths, argument values, tokens, response bodies,
redirect locations, or library exception details. JSON stdout preserves the
complete typed integration response, including version and configuration
messages. Owner connection details fail closed. No role-probing request
precedes status. The system command requires the integration role, and neither
command supplies the trusted peer/user metadata required by ingress.

The `unlock` command instead uses `HOME_ASSISTANT_URL` and
`HOME_ASSISTANT_TOKEN`. It authenticates through the normal HA WebSocket API,
discovers the configured app, and requests an ingress session bound by HA to
the actual administrator. The app still checks the trusted Supervisor peer and
its allowed-user list. No caller-supplied HA identity is trusted. HTTPS is
required except on loopback; normal certificate checks, no redirects, and no
ambient proxies apply to this flow.

Dedicated `/v1/cli/session`, `/v1/cli/trust`, and `/v1/cli/attempt` routes require
`X-FileVault-Client: native-cli` and reject browser Origin and Fetch Metadata
headers. This header is an anti-CSRF signal, not authentication. Native and
browser grants cannot cross channels. User, cookie, nonce, expiry, SSH identity,
explicit intent, global concurrency, and cooldown checks still apply.

The CLI displays the SSH target and fingerprint before hidden password entry.
New identities require interactive confirmation; `--password-stdin` requires
existing trust. Automation may supply one password line from a secret-manager
child process, never from arguments, environment, files, or an agent transcript.
HA sessions, grant cookies, nonces, and passwords are transient and never saved.
Preparation may wait for SSH startup, but password submission occurs once.
Lost attempt responses lead only to observation, never resubmission. Exit 0
requires fresh independent normal-runtime evidence, including for an already
running Mac. This is not desktop-login or application-health evidence.

## Manual SSH identity and intent

The SSH handshake verifies the server's key-exchange signature and retains the
same connection through confirmation and authentication. Certificates are
rejected. A candidate identity alone is not authorization to send a password.
New and changed identities require a distinct, authenticated confirmation action
before password entry. A changed identity is never silently accepted or
replaced. Users must verify its displayed fingerprint through a trusted source.
An explicitly provisioned normal-runtime public identity can bootstrap trust.

Public server identities persist in owner-only /data/ssh_known_hosts.
The app uses standard known_hosts records, an append-only explicit trust step,
readback, bounded file size/identities, and regular-file/permission checks.
A new connection always checks its identity against remembered trust. Any rekey
on the retained connection must use that same selected identity. The manual
path does not require an extra pre-authentication rekey or reconnect.

The server binds the candidate connection to a random 60-second nonce, secure
session cookie, allowed HA user, client channel, and manual/automatic action.
Browser grants additionally require the exact HTTPS origin.
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

Passwords enter only through the reviewed UI, the hidden CLI prompt, or the
explicit stdin automation path described above. Never expose them to agent
conversations, chat, screenshots, DOM/request inspectors, or browser automation.
They must not enter options, files, command arguments, environment,
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
Browser mutations require exact HTTPS Origin and same-origin Fetch Metadata;
native mutations use the separate HA-authenticated channel described above.
Both require no query payload, bounded body size, nonce/session/user/channel
binding, expiry, and atomic consumption.
The read-only integration token cannot open the UI, remember identities, create
an SSH grant, or submit a password.

Connection history is ingress-only and never accessible with the integration
token. SQLite stores only timestamps, sequence, run state, endpoint outcome
enums, fixed error categories, and a hash of endpoint configuration. No target
names, login names, credentials, host keys, resolver configuration, or raw
diagnostics enter the database. History is capped at 1,000 runs and 30 days,
filtered to matching endpoint settings, and never consumed by runtime policy.
Accepted checks finish independently of the HTTP waiter and drain before
SQLite shutdown. Restart marks incomplete records interrupted; it never
replays a check or trusts a server. All checks remain pre-authentication.

The controller bounds pending grants, serializes preparation, permits one
in-flight attempt, and applies 60-second startup/attempt cooldowns. Connection
and identity checks have five-second limits; authentication has a 30-second
limit. A cancelled task cannot create an automatic retry. A failed or ambiguous
attempt needs a new explicit user action after applicable limits.

## Shared profile, runtime evidence, and migration

One mac profile supplies the LAN unlock target, optional Tailscale target, one
SSH port and username. No second manual or automatic authentication group
exists. Normal checks use no account password or client private key. Server
identity verification remains mandatory and separate from account login.

A fresh SSH key exchange at the configured Tailscale address must resolve to a
tailnet-range socket peer and match the same trusted server identity store as
LAN manual SSH. Cached controller online state, an SSH banner, an untrusted
key, a LAN alias, or stale evidence cannot establish Running. A live verified
Tailscale response is positive normal-runtime evidence from the existing
normal-OS Tailscale service; desktop login and application health are separate.
Actual app-container reachability and cold-boot behavior need deployed checks.

Failure never proves FileVault locked or power off. DNS failure, timeout,
missing identity verification, unreachable peer, and stale evidence retain
separate safe statuses. Manual LAN login remains available independently.
No new service, credential, tailnet membership, ACL, or network grant is added.

Trusted LAN SSH alone remains SSH online. Optional advanced phase detection
still requires distinct phase-exclusive identities and supervised calibration.
Missing preboot enrollment is a setup note, not an invalid normal connection.
Normal runtime never fabricates manual_enrollment_verified or preboot evidence.

Legacy migration compares every specified target and rejects divergence before
any transport can operate. Canonical options have one mac profile. The explicit
migration command preserves input, creates one new mode-0600 output, refuses
unsupported credential fields, and never prints values. Existing read-only
integration credentials may be present in exports; both files stay private.
Supervisor filters unknown schema fields before writing runtime options, so
HA upgrades require preflight export/migration and are marked breaking to
prevent unattended option loss. No app-side Supervisor mutation grant is used.

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
Use the reviewed password-entry path and independent service checks.

Publication requires source/history/private-data review, exact-head CI,
negative identity/intent/expiry/concurrency tests, native container smoke,
license checks, and explicit publication approval. Source prereleases must
state hardware limitations. Installation and hardware actions are separate.
No private vulnerability-reporting channel is configured; never post secrets
or deployment details in a public pull request.
