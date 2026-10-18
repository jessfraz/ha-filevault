# FileVault

FileVault recovery UI for Home Assistant, using the same Rust/Dropshot service,
embedded dashboard, and Python integration structure as
[Maintenance](https://github.com/jessfraz/ha-maintenance) and
[Shipments](https://github.com/jessfraz/ha-packages).

This is a development prototype. It has a masked recovery form, bounded
request handling, a transport interface, and a read-only HA status adapter.
Synthetic fixtures exercise the complete request flow. The real SSH adapter
verifies a configured public host key but reports `unknown` and cannot send a
password. Preboot detection and real unlock remain disabled. No release image
exists.

![FileVault status preview](docs/screenshots/status-desktop.jpg)

Synthetic status preview. [Mobile layout](docs/screenshots/status-mobile.jpg).

## Requirements

This project targets Apple's FileVault unlock over SSH on Apple silicon with
macOS 26 or later, Remote Login enabled, and network connectivity available.
It has not validated a preboot detector or an unlock against a real Mac.
See [Apple's FileVault documentation](https://support.apple.com/guide/security/managing-filevault-sec8447f5049/web).

The eventual executor must run independently of the locked Mac. A verified
preboot SSH host identity is required before accepting a password. An open SSH
port, version banner, or missing application service does not prove FileVault
is locked. See [security requirements](SECURITY.md).

## Structure

- `src/`: Dropshot service, state policy, request guard, and SSH handshake
  probe.
- `web/`: embedded dashboard using the reference apps' CSS and layout.
- `custom_components/filevault/`: read-only HA status adapter.
- `filevault/`: HA app metadata and installation notes.
- `tests/`, `tests_web/`, `tests_ha/`: Rust, browser-policy, and adapter checks.
- `.github/`: CI, gated container builds, security checks, and Dependabot.

The app has no database, saved password, generated unlock credential, or HA
unlock action. Those are intentional differences from the task and shipment
services. [Architecture notes](ARCHITECTURE.md) describe the boundaries.

## Development

Use Rust stable, Node.js, Python 3.14, uv, and just. `nix develop` provides the
reference development environment.

```sh
just check
just openapi
```

The Rust tests exercise pinned SSH handshakes, ambiguous status, single-use
requests, identity changes, concurrency, timeouts, and loopback HTTP validation.
JavaScript fixtures cover masked-field clearing and UI cancellation. HA tests
exercise adapter lifecycle and the read-only status boundary. These checks do
not certify deployment, proxy logging, or real preboot behavior.

## Home Assistant and HACS

The Python integration can be added to HACS as a custom repository of type
Integration, using `https://github.com/jessfraz/ha-filevault`. It provides a
read-only status sensor and requires an independently running backend plus
its read-only status credential. It does not install the backend or provide
a working unlock operation. This project is not listed in the HACS default
catalog.

The integration includes its own PNG brand assets and entity icons. HA app
icon/logo assets are included under `filevault/`. App image publication and
production recovery remain disabled while hardware validation is pending.

## Configuration

Ingress accepts only the configured Supervisor peer and an explicit user-ID
allowlist. The default empty allowlist denies access. The HA app metadata
exposes only `allowed_user_ids`; there is no Mac password option.

Developer JSON options additionally accept an HTTPS `frontend_origin` without
a path and an optional `ssh_probe` containing `host`, `port`, and
`pinned_public_key`. A probe requires an independently verified public key.
It performs key exchange only and cannot enable recovery. No target is included
in the source or app defaults.

An optional `FILEVAULT_STATUS_TOKEN` enables the separate read-only listener at
`FILEVAULT_BIND` (default `127.0.0.1:8080`). It is a service credential,
separate from a Mac password. The app generates and stores no credential. The
HA adapter can
pair explicitly with that origin and read-only credential. The app package
does not expose this listener or automate pairing yet.

Do not use this prototype for recovery or enter a Mac password into it.
Private deployment configuration belongs outside the source tree.

## Contributing

Issues and the wiki are disabled. Submit improvements through pull requests,
using fictional fixtures. See [CONTRIBUTING.md](CONTRIBUTING.md) and
[SECURITY.md](SECURITY.md) before changing the credential path.

## License

MIT. Reused reference code and styles retain their copyright notice.
