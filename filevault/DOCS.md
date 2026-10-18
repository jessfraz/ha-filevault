# FileVault app

The app uses managed /data, ingress 8099, and optional internal read-only API
8080 with no host mapping. Initial ownership setup drops to UID 10001. There
are no host mounts, privileged mode, Docker/Core API access, or broad Supervisor
grants. Existing read-only integration pairing remains unchanged.

The HACS integration also provides bounded Assist queries and redacted native
diagnostics. Expose its status sensor to Assist to opt into the read-only tools.
Import notification blueprints separately and select notification actions.
See the repository README for setup. These features never send an unlock
request or use a login password.

## Configure one Mac

In Mac connection, set host to the LAN unlock hostname, port to its SSH port,
and username to the account used for manual password login. These values exist
once. manual_enabled preserves the choice to permit manual requests.

Optionally set tailscale_host to this same Mac's actual Tailscale IP or full
MagicDNS hostname. It uses the same SSH port and trusted server identity store.
Keep the full tailnet hostname when using MagicDNS. If name lookup fails,
verify Home Assistant's internal DNS forwarding to the Tailscale app's proxy.
No tailnet credentials or permissions are added. The app container needs an
existing route to that address; a host-level successful probe is insufficient
to establish container reachability.

Set allowed_user_ids explicitly and frontend_origin to the exact HA HTTPS
origin without a path or trailing slash. Never enter a login password, private
key, or SSH client-key credential into app options.

## Connect with SSH

Connection checks save bounded history in `/data/filevault.sqlite3`, using
SQLite migrations and WAL like Shipments and Maintenance. Saved history shows
the latest checks and last successful SSH/identity observations for the current
endpoint settings, up to 1,000 runs for 30 days. It contains no credentials,
target addresses, host keys, resolver configuration, or raw errors. Include
managed app data in the normal Home Assistant backup.

Checks stay above the main controls until all configured endpoints pass DNS,
TCP, and trusted SSH identity checks. Successful checks move below the controls
for 30 seconds; stale results return to the top. You can rerun them in either
position. History never supplies current Running evidence. A browser that
stops waiting does not cancel an accepted check; its bounded result is saved.

Click outside the password dialog or press Escape to dismiss an unsubmitted
attempt. The unsent password clears and focus returns to the opening control.
While a submitted operation is in progress, dismissal waits for its result;
there is no cancellation or retry disguised as closing the dialog.

Open the app and choose Connect with SSH. The displayed LAN account comes from
the same Mac profile shown above status. A new or changed server identity needs
independent fingerprint verification, a checked confirmation, and a click on
Trust this SSH server before password entry becomes available. A changed key
is never silently accepted. Public host identity is different from a client
key used for account authentication; no client key is required here.

After trust, confirm the target and one password attempt, enter the password
for that attempt, and submit once. The field clears immediately. Authentication
and disconnect results do not prove FileVault unlock or normal startup. There
is no terminal, command execution, automatic retry, or saved login password.
You can also verify server identity and cancel without entering a password.

The existing startup and attempt cooldowns are 60 seconds. A new explicit
connection is required after an expired grant, cancellation, or failed attempt.

## Read status

A fresh Tailscale SSH response with the trusted Mac server identity establishes
positive normal-runtime evidence. It uses no account password or client key.
The actual peer must be in a Tailscale address range. A bare banner, cached
controller presence, LAN response, or stale observation cannot establish this
Running state. Required applications and desktop login remain separate checks.

No Tailscale response means unavailable and possibly needing unlock, with
network failure still possible. Name resolution, timeout, and identity setup
have separate guidance. Manual LAN SSH remains available when configured.
Verify this app container's route before claiming deployed live detection.
Actual power-loss and FileVault cold-boot behavior remain unvalidated.

Advanced FileVault preboot suggestions use optional separately verified phase
identities in automatic. They contain no host, port, or username. Missing
preboot enrollment is a setup note and does not block normal Tailscale checks
or manual password SSH. Never mark enrollment verified from normal runtime.

## Migrate alpha.1 or alpha.2

The release is listed in breaking_versions to prevent unattended installation
across the schema change. Before updating, export the current saved app options
privately. Keep existing app data, pairing credentials, and ssh_known_hosts.
Supervisor discards unknown schema fields before passing options to the app;
do not rely on backend legacy parsing as an HA migration mechanism.

Run the new binary against that private export:

```sh
filevault --migrate-options original.json --migration-output canonical.json
```

The original is preserved. A new owner-only canonical file contains one mac
profile, automatic evidence settings, and the original access/pairing options.
It contains no legacy connection groups. Conflicting hostnames, ports, accounts
or identities stop migration with a safe error; resolve the original options
explicitly rather than guessing. Never print or upload either options file.

After the new schema is installed, the HA mutation owner applies canonical
options using Supervisor, restarts only this app as required, and reads back
its values privately. Check versions, continued startup, one editable target,
manual capability, no invalid-profile error for missing preboot enrollment,
private file permissions, existing pairing, and live tailnet reachability from
inside the app container. Coordinate any integration/Core restart separately.

Only the user enters a real password, with agent observation and inspection
off. Use loopback-only synthetic fixtures for automated UI checks. Keep PDU
work on hold until the corrected deployed app has been verified.
