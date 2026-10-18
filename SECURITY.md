# Security design and release gates

This local prototype has an ephemeral request path tested with dummy values.
The production transport cannot send a password and always reports unknown.
The tests do not establish successful FileVault unlock. Do not submit a Mac
password to the prototype.

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

1. A verified preboot detector, trusted key enrollment, exact authentication
   conversation, and identity-bound normal-runtime confirmation.
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
