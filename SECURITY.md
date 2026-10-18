# Security design and release gates

This experimental implementation is tested only with synthetic SSH peers.
Recovery is disabled by default. A manually verified profile can enable one
SSH password attempt only when independently trusted preboot and runtime host
keys are distinct. No generic Apple preboot signature is assumed. Shared keys
are unsupported, and actual Mac behavior has not been validated.

## Credential boundary

The user must enter and submit the password directly in the final reviewed
UI. Agents, chat, test tools, screenshots, request inspectors, and browser
automation must never receive a real password.

The password must not enter Home Assistant entities, attributes, events,
service calls, automations, history, recorder, traces, or notification data.
Do not use an `input_text` entity, including one styled as a password field.

The dedicated ingress endpoint accepts credential bytes only in a
small HTTPS request body. It must never appear in a URL, header, command
line, environment variable, file, cookie, exception, or log. No analytics,
third-party scripts, browser storage, service workers, or password caching.

Ingress passes requests through Home Assistant and Supervisor processes.
Those proxies transiently handle request bodies. Before deployment, verify
that no layer logs bodies, dumps inputs, or buffers this route to disk.
The design does not promise that the password bypasses proxy memory.

Clear the field after submission, expiry, or navigation. Use temporary
buffers, best-effort clearing, short process lifetimes, and disabled crash
dumps. Browser, library, and runtime copies, swapping, and compromised
clients cannot be absolutely ruled out. Do not claim guaranteed erasure.

## Authentication and request integrity

- Use the supported ingress authentication boundary. Accept requests only
  from the trusted Supervisor peer and an explicitly allowed user identity.
  Missing identities fail closed. Sidebar visibility is not authorization.
- Require HTTPS and a reviewed origin. Validate Origin and Fetch Metadata.
  Apply a restrictive CSP and no-store/referrer policies.
- Bind cryptographically random, short-lived, single-use request nonces to
  the authenticated user and session. Consume atomically before attempting
  SSH. Reject replay, expiry, parallel submissions, and unexpected fields.
- Permit one in-flight attempt per configured target, with bounded connect,
  authentication, and completion deadlines. No automatic credential retry.
  Apply conservative attempt limits and a startup cooldown.
- Never turn the endpoint into a general SSH client, terminal, proxy, or
  command runner. Host, account, port, and protocol profile are reviewed
  configuration, not browser-supplied request parameters.

## SSH and state evidence

- Enroll the preboot public host identity from independently trusted
  evidence. Do not silently trust a scan, accept a new key, or disable host
  checking. Normal-runtime and preboot identities may require separate pins.
- Verify SSH key exchange before interpreting preboot protocol evidence or
  sending a password. Plaintext SSH version strings are not identity proof.
- Do not infer locked from an open port or absent runtime service. A locked
  state requires a reviewed, platform-specific preboot detector. Until that
  detector is validated, report unknown and keep the form unavailable.
- Repeat status verification immediately before submission. Enforce all
  decisions on the server, even if a client forces the form to be visible.
- Use a maintained, reviewed SSH library with a pinned dependency set.
  Reject unexpected authentication conversations. Do not use shell
  interpolation, command-line passwords, agent forwarding, or a general PTY.
- SSH closing is not proof of success. Clear credentials, then wait for
  fresh identity-bound normal-runtime proof. Otherwise report booting or
  unknown without resubmitting a password.

## Release gates

Before deploying or publishing a working implementation, review:

1. Supervised phase-key calibration for the exact Mac and OS: independently
   trusted, distinct, stable preboot/runtime keys; compatible pre-authentication
   rekey and password authentication; expected disconnect and runtime
   transition.
   Leave the manual verification gate false if any fact is unproven.
2. The full HTTP/proxy/SSH implementation and dependency supply chain.
3. Negative tests for identity mismatch, CSRF, replay, expiry, concurrency,
   ambiguous states, timeouts, repeated prompts, and false success.
4. Dummy-sentinel tests proving absence from every observable persistence
   and logging surface. Never use a real password for those tests.
5. Minimum container privileges, no unnecessary host mounts or management
   API access, and the executor's independence from the locked target.
6. Publication approval, license choice, and a complete private-data scan
   of files, archives, metadata, and any future Git history.

No managed private vulnerability-reporting channel is configured. Do not
post credentials, deployment details, or exploit material in a public pull
request. Establish a private disclosure channel before a working recovery
release.

## Implemented phase-identity profile

The profile is an administrator's manually calibrated trust statement. A pin
alone never discovers phase. Set `manual_enrollment_verified` only after
independent supervised evidence proves the configured keys are exclusive to
preboot and normal runtime. Recalibrate after OS or SSH identity changes.
There is no shared-key fallback, banner matching, key scanning, or automatic
acceptance. Invalid or identical keys fail configuration validation.

The adapter verifies the key-exchange signature and exact pinned public key,
rejects certificates, and rekeys the retained connection before one password
method. It never requests a shell, runs a command, opens a PTY, forwards an
agent, or falls back to keyboard-interactive or another authentication method.
Its socket is closed when the attempt is dropped or cancelled.

Credential bytes move into russh's owned password method, which zeroizes its
String on drop and redacts its Debug output. The application installs no
input-bearing logger. Library, HTTP, browser, and proxy copies remain a
best-effort boundary, not guaranteed erasure or proof about deployed proxies.

After success or an ambiguous disconnect, the password is not reused. Only a
fresh handshake to the separately enrolled normal-runtime key can produce
Running. This means normal SSH runtime availability, not desktop login or all
application health. Without that proof, the result stays booting/unknown.

A source prerelease may publish synthetic validation and disabled-by-default
packaging. It must say hardware behavior is unvalidated and must not claim
production recovery readiness. Installation and supervised real-password tests
remain separate actions with concrete approval and the user present.

## Persistent pairing access

The app's automatic pairing option creates one read-only service credential in
owner-only `/data/credentials.json` at approved startup. Atomic publication
preserves it across restarts and concurrent starts. Only that token and the
Supervisor-provided internal origin enter authenticated discovery. Supervisor
and HA Core consequently gain read-only status access, not unlock authority.

HA confirmation precedes the backend credential probe and config-entry write;
reauthentication rediscovers the same app and confirms replacement. A separate
owner API credential is unnecessary and is not generated. The optional manual
status token is for standalone setup with automatic pairing off. None of these
persistent service credentials is a Mac password. Include this persistent
access and credential creation in the concrete installation approval.
