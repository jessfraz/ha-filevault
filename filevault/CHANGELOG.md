# Changelog

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
