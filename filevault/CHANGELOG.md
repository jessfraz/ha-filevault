# Changelog

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
