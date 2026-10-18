# Configuration

The app currently serves status through authenticated ingress. Add the intended
HA user IDs to `allowed_user_ids`; an empty list denies all users. This is not
an account-password field.

The status adapter is separate from ingress. A developer can configure an
explicit backend origin and a separately supplied read-only service token.
The app does not generate tokens, expose that API port in its HA metadata, or
announce discovery. Automatic pairing remains unimplemented.

No Mac host, account, fingerprint, password, or private topology is included in
the distributed configuration. Do not place deployment files in this repository.

The standalone developer service accepts an optional `frontend_origin` and
`ssh_probe` in its JSON options. The latter contains a host, port, and pinned
public key and performs key exchange only. These options are not exposed in
the HA app metadata. No option enables synthetic test transports or real
password submission.

# Before release

Validate a password-free preboot detector, independently verify the target's
preboot host identity, review the complete credential path, and test proxy
logging and buffering with dummy data. Coordinate any installation and restart
with the deployment owner. No real Mac power-cycle test is part of the scaffold.
