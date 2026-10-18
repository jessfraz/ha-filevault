# FileVault

Password-based SSH unlock for Home Assistant, with one Mac profile, an optional
Tailscale running check and optional boot-phase suggestions. It follows
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

## One Mac connection

Enter the LAN hostname, optional Tailscale address, SSH port, and username once
in **Mac connection**. The same profile drives manual password SSH, automatic
LAN observations, and the optional Tailscale running check. There is no separate
manual host, username, port, or authentication group.

```json
"mac": {
  "host": "mac.example.invalid",
  "tailscale_host": "100.64.0.2",
  "port": 22,
  "username": "your-account",
  "manual_enabled": true
}
```

Use the Mac's actual Tailscale IP or full tailnet hostname. The example is a
placeholder. A numeric address also works when the HA app cannot resolve its
MagicDNS name. Existing HA routing and tailnet permissions must already allow
the connection; the app adds no membership, ACL, DNS, or network grant.

## Manual password SSH

Open **Connect with SSH** in authenticated ingress. It uses the shared profile's
LAN target even when automatic status is unavailable, unknown, or running.
Recognized servers proceed to account confirmation and temporary password
entry. A new or changed server displays its fingerprint and requires a separate
explicit identity-verification step before password entry. The confirmation is
a working button flow, not an instruction to copy a key into another setting.

Server identity verification is different from client-key authentication.
Manual login uses one ephemeral password and does not require a client key.
Only public server identities persist in owner-only /data/ssh_known_hosts.
You can verify the identity and cancel before entering any password; automatic
checks can then use that trusted identity without a login password.

The retained cryptographic connection and any rekey use the selected identity.
There is no reconnect, shell, command, PTY, forwarding, method fallback, or
automatic password retry. Accepted manual authentication reports authenticated,
not FileVault-unlocked. Ambiguous disconnect reports unconfirmed. Check status
and required services separately.

## Automatic running checks

The optional Tailscale check makes a fresh SSH handshake to the shared profile's
Tailscale address and SSH port, requires an actual tailnet peer address, and
matches the server identity against the same trusted LAN identity store. It
uses no account authentication, password, client key, controller API, or cached
peer-online flag. A fresh verified response is positive normal-runtime evidence
and reports Running. It does not prove desktop login or application health.

DNS failure, timeout, missing identity verification, or unreachable tailnet is
reported distinctly. Failure may mean the Mac needs unlocking, or networking
may be unavailable. It never proves the Mac is locked or powered off and never
blocks an explicit manual LAN connection. Old observations cannot establish
Running. A trusted LAN handshake by itself means only SSH online.

The Tailscale path relies on the existing Mac's normal-OS Tailscale service.
Its actual cold-boot availability and the app container's route must be checked
in the deployed environment. Wi-Fi presence is not used as unlock evidence.

**Advanced FileVault preboot suggestions** are separate optional evidence
settings, with no duplicate connection target. Missing preboot enrollment is a
setup note and does not invalidate the Mac connection or Tailscale check.
Distinct independently verified phase identities and supervised enrollment
remain required for the advanced classifier; shared phase keys cannot classify
boot phase. A normal-runtime observation never fabricates preboot enrollment.

Apple supports FileVault SSH unlock on Apple silicon with macOS 26 or later,
Remote Login enabled, and networking:
[Apple documentation](https://support.apple.com/guide/security/managing-filevault-sec8447f5049/web).
This does not establish compatibility of this prerelease with a particular Mac.

## Upgrade from alpha.1 or alpha.2

This is a breaking configuration change, blocked from unattended app updates.
Supervisor filters removed schema fields before writing runtime options, so an
HA upgrade needs a preflight migration of its original saved options.

```sh
filevault --migrate-options original.json --migration-output canonical.json
```

The command writes one new mode-0600 output, preserves the original bytes, and
never prints option values. Keep both files private because existing read-only
integration credentials may be included. It refuses conflicting targets,
unsupported password fields, and malformed input. It never selects a divergent
target silently or changes a provider itself.

The HA mutation owner exports the current options privately before updating,
runs this command, then applies the canonical options through Supervisor after
the new schema is installed. Preserve app data and existing trusted identities.
Do not restart unrelated apps. Standalone runtime parsing accepts legacy input
with the same conflict rules, but it does not rewrite Supervisor-managed files.
See [app instructions](filevault/DOCS.md) for verification.

## Home Assistant app and pairing

Add `https://github.com/jessfraz/ha-filevault` to the HA app-store repositories.
Review the exact prerelease, image digest, permissions, and target before
installing or updating. The app image is
`ghcr.io/jessfraz/ha-filevault:<version>`, native amd64 and arm64.

- `allowed_user_ids`: explicit HA users permitted through ingress; empty denies
  access. The configured Supervisor peer is also checked.
- `frontend_origin`: exact HTTPS browser origin, without path or trailing slash.
- `mac`: the single shared connection, with optional Tailscale address.
- `automatic`: optional advanced phase evidence, with no connection fields.
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
password entry. The user enters it directly, with agent observation off.
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

## Ask Assist

Expose the FileVault status sensor to Assist and use an agent with the Device
control API enabled. Two explicit read-only tools are available:

- `filevault__status`: latest status, freshness and capability flags.
- `filevault__configuration_health`: capability flags and error/setup-note
  counts.

Both take no arguments. Each call rechecks exposure, the active HA user's read
permission, and the loaded integration. They use the existing cache without a
new network request. Failed polls or observations older than 30 seconds return
unknown/unavailable. Connection identifiers, raw messages, tokens, host keys
and passwords are excluded. Voice requests without a user context are refused.
No model-provider account, credential, unlock or power tool is added. This uses
HA's native [LLM tool platform](https://contributors.home-assistant.io/core/internals/llm-api/).

## Native diagnostics

Use **Download diagnostics** on FileVault in Devices & services. The integration
returns an allowlist of status flags, observation age, configuration counts and
entry state. Connection and credentials are redacted; entry data, titles,
identifiers, unknown future fields, raw messages and exceptions are omitted.
Downloading makes no backend request. HA adds its standard environment metadata
around this integration payload.

## Notification blueprints

Import a blueprint in **Settings → Automations & scenes → Blueprints**, then
choose the FileVault status sensor and notification actions. Nothing is
installed or enabled automatically. The YAML is included in the source archive:

- [Needs attention](blueprints/automation/filevault/needs_attention.yaml): notify
  after two minutes of an attention state; cooldown defaults to 30 minutes.
  Short flaps, attribute changes and initial entity creation stay quiet.
- [Runtime available again](blueprints/automation/filevault/running_again.yaml):
  notify after a transition to Running remains stable for 30 seconds, with a
  configurable 10-minute cooldown.
- [Daily status](blueprints/automation/filevault/daily_status.yaml): digest at a
  chosen local time (08:00 by default). Running stays quiet unless enabled.
  A two-hour cooldown suppresses repeated local times during DST fallback.

Notification fields can use `{{ title }}`, `{{ message }}` and `{{ status }}`.
Choose notification actions only. No blueprint uses a password, unlock request,
restart or power-cycle action. Missing status never proves locked; Running does
not prove desktop or application health. Debounce resets on automation reload;
cooldown uses HA's `last_triggered` state.

## Development and release

Use Rust stable, Node.js, Python 3.14, uv, and just. `nix develop` supplies the
reference tools. Run `just check`, `just security`, and `just container`.
`just openapi` regenerates the API description. CI runs frozen uv, Ruff, ty,
pytest, Rust tests/lints, browser checks, and native amd64/arm64 container
smoke.
All SSH tests use ephemeral loopback peers and synthetic credentials.

With librsvg installed, run `scripts/render-brand` to regenerate transparent
light/dark integration PNGs and matching app icon/logo from `web/brand.svg`
and `web/brand-dark.svg`. Flat outlines and neutral fills match Shipments
and Maintenance. No sibling assets are modified.

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
