# FileVault

Password-based SSH unlock for Home Assistant, with a permanent manual connection
option and optional automatic boot-phase suggestions. The service follows
[Maintenance](https://github.com/jessfraz/ha-maintenance) and
[Shipments](https://github.com/jessfraz/ha-packages): Rust/Dropshot, an embedded
light/dark UI, HA ingress, and a read-only Python integration.

**Experimental prerelease. Real Mac recovery has not been validated.**
The manual feature uses host, port, username, and a password entered for one
attempt. It does not require client-key authentication or copied phase keys.
It does not open an interactive terminal.

![FileVault status preview](docs/screenshots/status-desktop.png)

Synthetic preview. [Mobile layout](docs/screenshots/status-mobile.png),
[dark theme](docs/screenshots/status-dark.png), and
[server identity confirmation](docs/screenshots/manual-identity.png).

## Manual password SSH

Configure the target in `manual_ssh` with `enabled`, `host`, `port`, and
`username`. Open **Connect with SSH** in authenticated ingress. Recognized
servers proceed to account confirmation and temporary password entry. A new or
changed server displays its fingerprint and requires a separate explicit
identity-verification step before the password field is enabled. A changed
identity is never silently accepted. No public-key text needs to be copied into
manual configuration.

Only public server identities are remembered in owner-only
`/data/ssh_known_hosts`; no account password is saved. The first handshake and
password use the same cryptographic connection, with exact identity checking
through any server rekey. No reconnect, shell, command, PTY, forwarding,
authentication-method fallback, or automatic password retry occurs.

Manual SSH remains available when phase is unknown, automatic detection fails,
or normal runtime is detected. Each attempt needs a fresh user/session/origin
bound grant and explicit confirmation. An accepted password reports
**authenticated**, not FileVault-unlocked. A disconnect reports **unconfirmed**.
Check status and required services separately.

Existing `ssh_recovery` host/port/username settings are reused when the new
manual target is blank; options are not rewritten. An explicitly provisioned
runtime server key can bootstrap the normal host identity. Incomplete automatic
profiles disable their suggestions and show a safe configuration message while
the dashboard and valid manual profile remain available.

## Status and optional automatic suggestions

A trusted SSH handshake can report **SSH online** without phase enrollment or
password authentication. It proves reachability of the trusted identity, not
FileVault state, desktop login, or application health. A host identity observed
only in normal runtime must not be claimed to prove its exclusivity to that
phase.

Automatic **Unlock FileVault** suggestions remain a separate advanced profile.
`ssh_recovery` uses independently trusted, distinct, phase-exclusive
`preboot_public_key` and `runtime_public_key`, plus `enabled` and
`manual_enrollment_verified`. Calibration is required for that classifier;
shared phase keys are unsupported. It has no generic banner detector or
trust-on-first-use. These requirements do not gate manual password SSH.
The automatic path repeats observations, rekeys the retained connection, and
requires a separate normal-runtime proof before reporting Running.

Apple supports FileVault SSH unlock on Apple silicon with macOS 26 or later,
Remote Login enabled, and networking:
[Apple documentation](https://support.apple.com/guide/security/managing-filevault-sec8447f5049/web).
This does not establish compatibility of this prerelease with a particular Mac.

## Home Assistant app and pairing

Add `https://github.com/jessfraz/ha-filevault` to the HA app-store repositories.
Review the exact prerelease, image digest, permissions, and target before
installing or updating. The app image is
`ghcr.io/jessfraz/ha-filevault:<version>`, native amd64 and arm64.

- `allowed_user_ids`: explicit HA users permitted through ingress; empty denies
  access. The configured Supervisor peer is also checked.
- `frontend_origin`: exact HTTPS browser origin, without path or trailing slash.
- `manual_ssh`: permanent manual password connection. Host/port/username only;
  the password belongs solely in the temporary app dialog.
- `ssh_recovery`: optional advanced automatic phase suggestions.
- `auto_pairing`: on by default. Approved startup creates/reuses a mode-0600
  read-only integration credential in `/data/credentials.json` and announces it
  privately through authenticated Supervisor discovery. HA confirmation occurs
  before credential validation or storage in Core. This is not a Mac password.
- `status_token`: optional 32–256-character service credential for explicit
  standalone pairing with `auto_pairing: false`. Never put an account password
  here. Empty disables that API when automatic pairing is off.

The app uses managed `/data`, initial ownership setup then UID 10001, ingress
8099, and an optional internal read-only API on 8080 with host mapping disabled.
It requests no privileged mode, host networking, Docker socket, host mounts,
devices, Core API token, or broad Supervisor API. Pairing uses only standard
self-info and discovery routes. Core dumps are disabled.

The executor, remote ingress, and recovery controller must survive loss of the
Mac. Review deployed proxy logging/buffering with dummy data before real
password
entry. The user enters the real password directly, with agent observation off.
Do not use this app's first unvalidated recovery attempt as its own fallback.

## HACS integration and icons

Add this repository as a HACS custom repository of type Integration. This is
**not** a default-catalog listing. HACS installs the read-only Python adapter,
which runs inside HA Core; review that trust boundary separately. App ingress
can be used without it. Coordinate any required Core restart.

The app and integration use identical 256-pixel brand icons and matching
512-pixel assets. The integration bundles `brand/icon.png` and `icon@2x.png`;
the HA app includes `icon.png` and `logo.png`. The standard app sidebar uses
its matching Material Design vault icon. Packaging checks enforce identical
PNG assets and dimensions.

The integration confirms Supervisor discovery, validates the integration role
through `/v1/system`, rejects owner credentials and redirects, and stores only
the read-only service credential. It exposes one enum sensor and no SSH/unlock
service, password-bearing entity, automation bridge, or transcript.

## Development and release

Use Rust stable, Node.js, Python 3.14, uv, and just. `nix develop` supplies the
reference tools. Run `just check`, `just security`, and `just container`.
`just openapi` regenerates the API description. CI runs frozen uv, Ruff, ty,
pytest, Rust tests/lints, browser checks, and native amd64/arm64 container
smoke.
All SSH tests use ephemeral loopback peers and synthetic credentials.

After committing a reviewed candidate, package it with:

```sh
scripts/build-release-artifacts --output /tmp/filevault-release
```

The source archive, integration ZIP, provenance, and SHA256SUMS contain
committed
public source only. Image publication requires an approved matching version tag
and the release gate. No deployment, password attempt, or power cycle is
performed by publication.

See [SECURITY.md](SECURITY.md), [ARCHITECTURE.md](ARCHITECTURE.md), and the
[app configuration guide](filevault/DOCS.md). Issues and wiki are disabled;
submit improvements with fictional fixtures through pull requests.

## License

MIT. Original icon assets and reused reference styles retain the license and
copyright notice.
