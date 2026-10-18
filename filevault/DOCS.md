# Configuration

The app uses managed /data, initial ownership setup then UID 10001,
authenticated
Supervisor ingress on 8099, and an optional internal read-only API on 8080 with
no host mapping. No privileged mode, host networking, host mounts, devices,
Docker socket, Core API token, or broad Supervisor management grant is
requested.

Set allowed_user_ids to actual approved HA users and frontend_origin to the
exact HTTPS browser origin without a path or trailing slash. Empty user lists
deny access. Missing or incorrect origin prevents password requests.

## Manual password SSH

manual_ssh contains enabled, host, port, and username. Enter no password or
client key in options. The manual feature is permanent and independent of
phase detection. A blank manual target can reuse the existing ssh_recovery
host/port/username; existing options are preserved. Explicitly disabling
manual_ssh disables the manual action.

Connect in the app, verify a new or changed server fingerprint through a trusted
source, and explicitly confirm that identity before password entry. Recognized
servers need only account/attempt confirmation and the temporary password.
Only public identities persist in /data/ssh_known_hosts, mode 0600. The saved
runtime public identity, if explicitly provisioned, can bootstrap normal trust.
Never copy or store a private key or account password there.

One user-confirmed password authentication request is sent over the same SSH
connection whose identity was displayed. No automatic reconnect, retry, shell,
PTY, commands, agent forwarding, or alternative authentication method occurs.
An accepted password is not proof of FileVault unlock. A disconnect is
unconfirmed. Refresh and verify required services independently.

## Status and automatic suggestions

Trusted SSH reachability can report SSH online without phase enrollment or
password authentication. It does not prove FileVault state or desktop login.

ssh_recovery is an optional advanced automatic classifier. Its two phase public
keys must be independently trusted, distinct, stable, and exclusive to their
phases before manual_enrollment_verified is set. Shared keys are unsupported
for automatic classification. Missing or invalid automatic keys show a safe
message and leave the dashboard/manual path available; they do not exit the app.
Do not fabricate enrollment proof to enable suggestions. Manual password SSH
does not require it.

## Pairing and persistence

auto_pairing defaults to true. Approved startup creates/reuses one read-only
integration credential in /data/credentials.json, mode 0600, and announces it
through authenticated Supervisor self-info/discovery. HA confirms before
validating or storing it in Core. It cannot submit an SSH password or trust a
server identity. No owner mutation credential is created.

For explicit standalone pairing, disable auto_pairing and provide a separate
32–256-character status_token. Never use an account password for status_token.
The optional Core adapter executes custom Python and stores the read-only token
in its config entry. Include that trust boundary, persistence, and any necessary
coordinated Core restart in installation/update approval.

Before a real attempt, review deployed proxies with dummy data, verify remote
HA ingress from the user's actual device, and establish control/recovery that
survives the Mac becoming unavailable. The user enters the password directly
with all agent observation inactive. No password belongs in chat, tools,
commands, files, HA options/entities/services/events/automations, traces, or
logs.
No hardware reboot or power test is implied by installation or a source release.
