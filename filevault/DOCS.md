# Configuration

The app follows the reference apps' GHCR multiarch image and Supervisor ingress
layout. It starts as an application with managed `/data`, then runs as UID
10001. No privileged mode, host network, host mounts, devices, Docker socket,
Core API token, or Supervisor-management API is requested.

`allowed_user_ids` permits only the listed HA users; empty denies everyone.
`frontend_origin` must be the exact HTTPS browser origin without a trailing
slash or path. It is required before recovery controls can become available.

`auto_pairing` defaults to true in the HA app. Starting it creates or reuses a
read-only integration credential in `/data/credentials.json`, mode 0600. The
app announces only its internal origin and that credential using Supervisor's
authenticated self-info/discovery route. No broader management API is requested.
HA requires confirmation before probing or storing it. This persistent access
and credential creation must be included in installation/start approval.

For explicit standalone/manual pairing, set `auto_pairing` false and provide
`status_token`, a read-only service credential of 32–256 printable characters.
An empty manual token disables the separate API. Never enter a Mac password.
The app listens internally on 8080 when either credential mode is enabled;
host mapping stays null. No credential is returned to its browser dashboard.

`ssh_recovery` contains `host`, `port`, `username`, `preboot_public_key`,
`runtime_public_key`, `enabled`, and `manual_enrollment_verified`. The two flags
start false. Supply public keys from independently trusted, supervised phase
calibration. Keys must differ. Identical keys, missing verification, unexpected
keys, or certificates cannot enable this recovery profile. Do not guess phase
from SSH banners or missing services. Recalibrate after OS or identity changes.

Only the user enters a Mac password, in the temporary ingress dialog during a
supervised attempt. No password belongs in these options, a HA service, entity,
automation, trace, log, or agent tool. There is no automatic password retry.

This prerelease is tested with synthetic SSH peers. Its exact preboot protocol,
phase-key behavior, app-network reachability, and deployed proxy buffering and
logging still require supervised validation. The normal runtime check proves
only the separately enrolled SSH identity, not desktop login or every service.

Installation, any necessary HA restart, and any later hardware power test need
separate concrete approval and coordination with other active HA work.
