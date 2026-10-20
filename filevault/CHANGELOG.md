# Changelog

## 0.1.0-alpha.9

- Show SSH online when LAN SSH is reachable and Tailscale is offline. Only
  verified FileVault preboot evidence displays Locked; manual SSH stays available.

## 0.1.0-alpha.8

- Show Locked when trusted LAN SSH is reachable and Tailscale is offline.
- Wait for SSH authentication and verified macOS startup after one password
  attempt, including the disconnect that can occur during FileVault unlock.
- Show live SSH activity and the final result in the dialog and recovery page.
- Separate connection failures from cooldown, with a countdown and retry time.
- Keep submitted attempts running when the browser navigates away, without
  resending the password.

## 0.1.0-alpha.5

- Add ingress-only connection checks for both shared-profile endpoints, with
  separate DNS, TCP port, and SSH identity results before authentication.
- Keep checks bounded, cancelable, and independent of password recovery and
  boot-phase evidence. Report only resolver IPs; never change DNS or trust.

## 0.1.0-alpha.4

- Match Shipments and Maintenance with transparent outlined safe icons, neutral
  fills, and light/dark variants. Preserve app and integration asset placement.
- Add bounded read-only Assist tools for status and configuration health,
  gated by entity exposure and current user read permission.
- Add native diagnostics with an allowlisted, redacted payload and no backend
  request, connection identifiers, credentials or raw exception text.
- Package opt-in attention, runtime-returned and daily-status notification
  blueprints with configurable targets, notification actions and debounce.
- Keep recovery and configuration unchanged; no automatic credentials, unlock,
  restart or power-cycle actions are added.

## 0.1.0-alpha.3

- Replace duplicate targets with one Mac connection shared by manual SSH and
  automatic observations, including an optional Tailscale address.
- Add deterministic private migration with conflict reporting and an explicit
  HA upgrade preflight; prevent unattended schema-changing updates.
- Use fresh, identity-verified Tailscale responses as positive normal-runtime
  evidence. Treat timeout, stale data, DNS failure and absence as ambiguous.
- Make missing preboot enrollment a setup note rather than an invalid profile.
- Show the shared connection and keep normal status checks independent of login
  passwords or client keys. Verify the full new/changed host confirmation flow.

## 0.1.0-alpha.2

- Add permanent manual password SSH with separate first-connection and changed
  server identity confirmation. Remember public host identities, never
  passwords.
- Permit explicit manual attempts for unknown or running phases; retain exact
  connection identity, one attempt, and no automatic retry or false unlock
  claim.
- Keep the dashboard running with safe errors for incomplete phase profiles.
  Reuse existing target settings without changing them or enrollment flags.
- Observe trusted SSH reachability independently of phase calibration.
- Match current sibling light/dark palettes and preserve identical app and
  integration brand icons.

## 0.1.0-alpha.1

- Add a manually calibrated SSH phase-identity profile, one password method,
  fresh same-connection key exchange, and separate pinned runtime confirmation.
- Reject unverified, shared, changed, or certificate identities; keep recovery
  disabled by default. No general preboot signature or real Mac validation.
- Add native multiarch HA app packaging, explicit ingress/user/origin options,
  an optional internal read-only status API, icons, and source release
  artifacts.
- Exercise authentication, disconnects, rejection, cancellation, identity
  conflicts, and absence of runtime proof with synthetic SSH servers.
