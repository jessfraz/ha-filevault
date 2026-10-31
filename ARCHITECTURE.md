# Architecture

Rust/Dropshot serves an embedded UI through HA ingress, with an optional
read-only Python coordinator. The stack, pairing, light/dark palette, and
packaging follow Maintenance and Shipments; reused MIT notices remain.

## One connection, independent evidence

Options contains one mac profile: LAN host, optional Tailscale host, one SSH
port, one username, and the manual permission flag. profiles::build derives
manual transport, LAN observer, advanced phase classifier, and Tailscale check
from that profile. No independent manual/automatic target is deserialized into
runtime options. automatic contains only optional phase evidence settings.

The Tailscale observer resolves only the configured Tailscale target, accepts
only a tailnet-range socket peer, performs fresh SSH key exchange, and compares
the server identity to the same known_hosts store as manual LAN SSH. It uses no
account authentication, controller API, presence cache, commands, or forwarding.
A fresh verified response establishes positive normal-runtime evidence. DNS,
timeout, identity, absence, and stale evidence remain distinct; none proves
FileVault locked or power off. Application and desktop health are separate.

A trusted LAN handshake alone is SSH online. The advanced phase classifier
still requires distinct independently calibrated phase identities. Missing
preboot enrollment is a setup note, independent of the Tailscale normal-runtime
check and manual password capability. No normal observation invents enrollment.

## Manual password action

POST /v1/manual/session uses the shared LAN target, retains a cryptographic SSH
connection, and returns a user/session/origin-bound 60-second grant, target,
fingerprint, and new/trusted/changed classification. Candidates cannot receive
a password before POST /v1/manual/trust separately confirms their public
identity on that same connection. It remains pinned through rekeys.

POST /v1/manual/attempt requires trusted identity and explicit intent, consumes
the grant atomically, and sends one password authentication request. There is
no client key, terminal, command, PTY, forwarding, method fallback, or retry.
Authentication, ambiguous disconnect, and authentication timeout are followed
by up to 120 seconds of fresh runtime checks when configured. Only verified
runtime evidence returns Running. The password is never resent. An accepted
attempt runs independently of its HTTP response, so browser navigation cannot
cancel delivery halfway through or strand the concurrency guard.

GET /v1/recovery returns the shared busy flag and cooldown remaining in
milliseconds. Its bounded, fixed-message activity log and final outcome are
visible only to the ingress user who submitted that attempt. Activity stays in
memory, contains no credential or raw server text, and is lost on app restart.
The integration token cannot access this route. The UI polls while active and
counts down locally between reads, showing connection failures separately.

The optional advanced action repeats enrolled preboot observations and rekeys
its retained connection before one password request. Its Running result needs
separate normal-runtime proof. Both actions share session binding, concurrency,
expiry, cooldown, and ephemeral password handling. Grants cannot change modes.

## API and migration

GET /v1/system supplies fast capabilities, fixed safe messages, and a read-only
shared connection summary to authenticated ingress. The integration role gets
no connection details. GET /v1/status adds fresh runtime evidence and a fixed
decision. Manual availability does not depend on status-query success. The UI
labels trusted LAN SSH with unavailable Tailscale as Locked; this display rule
does not grant automatic credential authority or assert calibrated phase keys.

Legacy groups are input-only migration formats. The resolver compares all
specified LAN hosts, ports, usernames, and server-identity settings before
constructing transports. Conflicting targets disable every SSH path and are
never silently prioritized. Canonical serialization contains one mac group.

The explicit --migrate-options command preserves the original, creates a new
mode-0600 output, and never prints values. Supervisor filters removed schema
fields before writing runtime options, so HA updates require a private export
and migration before applying the new schema. breaking_versions prevents an
unattended upgrade across this change. The app never rewrites managed options
or acquires a Supervisor mutation grant for migration.

## Credential boundary

Passwords travel only in bounded octet-stream bodies on dedicated ingress
routes, never URLs, headers, logs, options, HA entities/events/services,
recorder,
or traces. Fields and buffers clear before and after one POST and on cancel,
expiry, hide, or navigation. Rust Secret and russh's password method zeroize
owned memory. Socket shutdown closes cancelled attempts. Browser/proxy/library
copies remain best-effort memory boundaries.

Only the read-only integration credential and public known_hosts identities
persist under managed /data, with owner-only permissions. Pairing announces
only that integration credential through authenticated Supervisor discovery.
Core confirmation precedes token probing or storage. It cannot access the UI,
trust, grant, or password routes.

Ingress checks Supervisor peer and allowed user. Browser mutations additionally
require exact HTTPS Origin and same-origin Fetch Metadata. Native mutations
use a distinct client channel. Both require secure cookie, random nonce, action,
expiry, and bounded body.
Input-bearing request logging is discarded. The loopback browser fixture uses
synthetic SSH keys and only DUMMY_SENTINEL; it is not deployment validation.

## Native client

`cli/` is an independent Rust workspace package, `ha-filevault`, without a
server-library dependency. `system` and `status` use fixed external read routes
and client-owned `HA_FILEVAULT_*` configuration. Their typed integration DTOs
require null connection details and cannot acquire ingress authority.

`unlock` uses normal HA WebSocket authentication and ingress-session creation
with `HOME_ASSISTANT_*` configuration. HA binds the actual user identity; the
CLI never invents Supervisor headers or browser origins. The three `/v1/cli/`
routes share the existing SSH controller while binding grants to the native
channel. Browser and native grants cannot be interchanged.

The CLI waits for startup/cooldown before one bounded password submission, then
requires a fresh status with verified normal-runtime evidence. Interactive
password entry hides echo; explicit stdin input supports secret-manager child
processes with existing SSH trust. Credentials and sessions are not persisted.

The root default Cargo member remains `filevault`. Workspace checks include
real CLI processes against WebSocket/HTTP fixtures and the native ingress API
against real synthetic SSH peers. The flake's named/default package and app
build only the CLI on the already supported Nix platforms.

## Distribution

Native amd64/arm64 app images use /data, initial ownership setup then UID 10001,
ingress 8099, and optional internal read-only 8080 with host mapping disabled.
No privileged mode, host network, device, host mount, Core API, broad
Supervisor,
or new tailnet permission is requested. The optional HACS adapter runs in Core
and exposes one fixed enum sensor. It is not default-catalog listed.

App/integration brand PNGs match at 256 and 512 pixels. Packaging checks both
copies and dimensions, and archives only committed public source. Exact-head
CI, private-data review, native smoke, and explicit approval precede releases.
Deployment route and actual cold-boot/PDU verification remain separate.
