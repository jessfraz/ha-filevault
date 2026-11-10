#!/usr/bin/env bash
set -euo pipefail
image=${1:?image required}
architecture=${2:?architecture required}
actual=$(docker image inspect "$image" --format '{{.Architecture}}')
test "$actual" = "$architecture"
docker run --rm --read-only --network none --user 10001:10001 "$image" --version

# Exercise actual HA options and credential bootstrap on ephemeral RAM only.
container=
volume=
restored_volume=
cleanup() {
    if [[ -n "$container" ]]; then
        docker stop --time 5 "$container" >/dev/null 2>&1 || true
        docker rm "$container" >/dev/null 2>&1 || true
    fi
    if [[ -n "$volume" ]]; then
        docker volume rm "$volume" >/dev/null 2>&1 || true
    fi
    if [[ -n "$restored_volume" ]]; then
        docker volume rm "$restored_volume" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT
options='{"allowed_user_ids":["fixture-user"],"frontend_origin":"https://ha.example.invalid","status_token":"","auto_pairing":true,"ssh_recovery":{"enabled":true,"host":"192.0.2.1","port":22,"username":"fixture-user","preboot_public_key":"","runtime_public_key":"","manual_enrollment_verified":false}}'
container=$(docker run --detach --read-only --network none --user 10001:10001 \
    --tmpfs /data:rw,noexec,nosuid,nodev,size=1m,uid=10001,gid=10001,mode=0700 \
    --env SUPERVISOR_TOKEN=supervisor-only-dummy-token --entrypoint /bin/sh \
    "$image" -c 'printf "%s" "$1" > /data/original.json; sha256sum /data/original.json > /data/original.sha256; /usr/local/bin/filevault --migrate-options /data/original.json --migration-output /data/options.json; sha256sum /data/options.json > /data/options.sha256; exec /usr/local/bin/docker-entrypoint.sh --ingress-bind 127.0.0.1:8099 --ingress-peer 127.0.0.1' sh "$options")
probe='exec 3<>/dev/tcp/127.0.0.1/8099; printf "GET /v1/system HTTP/1.1\r\nHost: localhost\r\nX-Remote-User-Id: fixture-user\r\nConnection: close\r\n\r\n" >&3; cat <&3'
response=
for _ in {1..20}; do
    if response=$(docker exec "$container" /bin/bash -c "$probe" 2>/dev/null); then
        break
    fi
    sleep 0.2
done
[[ "$response" == *'200 OK'* ]]
[[ "$response" == *'"manual_ready":true'* ]]
[[ "$response" == *'"configuration_errors":[]'* ]]
[[ "$response" == *'FileVault preboot detection has not been learned.'* ]]
# Measure from this isolated app container, without authentication or a host route.
check='exec 3<>/dev/tcp/127.0.0.1/8099; printf "POST /v1/connectivity HTTP/1.1\r\nHost: localhost\r\nX-Remote-User-Id: fixture-user\r\nOrigin: https://ha.example.invalid\r\nSec-Fetch-Site: same-origin\r\nContent-Length: 0\r\nConnection: close\r\n\r\n" >&3; cat <&3'
# Startup now runs the same probes automatically; wait for that bounded run
# before exercising the separate manual endpoint.
history='exec 3<>/dev/tcp/127.0.0.1/8099; printf "GET /v1/connectivity/history HTTP/1.1\r\nHost: localhost\r\nX-Remote-User-Id: fixture-user\r\nConnection: close\r\n\r\n" >&3; cat <&3'
for _ in {1..50}; do
    response=$(docker exec "$container" /bin/bash -c "$history")
    [[ "$response" == *'"state":"complete"'* && "$response" != *'"state":"checking"'* ]] && break
    sleep 0.2
done
response=$(docker exec "$container" /bin/bash -c "$check")
[[ "$response" == *'200 OK'* ]]
[[ "$response" == *'"dns":"resolved","tcp":"unreachable","ssh":"not_checked"'* ]]
[[ "$response" == *'"dns":"not_configured","tcp":"not_checked","ssh":"not_checked"'* ]]
[[ "$response" != *'fixture-user'* ]]
docker exec "$container" /bin/sh -c 'test "$(id -u)" -eq 10001; test "$(stat -c %a /data/credentials.json)" = 600; test "$(stat -c %a /data/ssh_known_hosts)" = 600; sha256sum --status --check /data/options.sha256; sha256sum --status --check /data/original.sha256; ! grep -Eq "manual_ssh|ssh_recovery|ssh_probe" /data/options.json; test "$(stat -c %a /data/options.json)" = 600'
printf '%s\n' 'Legacy migration produces one Mac profile; incomplete preboot remains a setup note; authenticated UI, manual SSH and private original options preserved'

# A disposable volume exercises process restart persistence on both native
# architectures. It contains only synthetic configuration and check outcomes.
docker stop --time 5 "$container" >/dev/null
docker rm "$container" >/dev/null
container=
volume=$(docker volume create)
options='{"allowed_user_ids":["fixture-user"],"frontend_origin":"https://ha.example.invalid","auto_pairing":true,"mac":{"host":"192.0.2.1","port":22,"username":"fixture-user","tailscale_host":""}}'
container=$(docker run --detach --read-only --network none \
    --env SUPERVISOR_TOKEN=fixture-supervisor-token \
    --env FILEVAULT_CHECK_INTERVAL_SECONDS=15 \
    --mount "type=volume,src=$volume,dst=/data" --entrypoint /bin/sh \
    "$image" -c 'umask 077; printf "%s" "$1" > /data/options.json; exec /usr/local/bin/docker-entrypoint.sh --ingress-bind 127.0.0.1:8099 --ingress-peer 127.0.0.1' sh "$options")
ready() {
    for _ in {1..30}; do
        if response=$(docker exec "$container" /bin/bash -c "$probe" 2>/dev/null); then
            [[ "$response" == *'200 OK'* ]] && return 0
        fi
        sleep 0.2
    done
    echo 'Authenticated fixture service did not become ready' >&2
    return 1
}
history='exec 3<>/dev/tcp/127.0.0.1/8099; printf "GET /v1/connectivity/history HTTP/1.1\r\nHost: localhost\r\nX-Remote-User-Id: fixture-user\r\nConnection: close\r\n\r\n" >&3; cat <&3'
ready
# No POST check is sent: startup and periodic observations must save themselves.
for _ in {1..50}; do
    response=$(docker exec "$container" /bin/bash -c "$history")
    [[ "$response" == *'"sequence":1'* && "$response" == *'"state":"complete"'* && "$response" != *'"state":"checking"'* ]] && break
    sleep 0.2
done
[[ "$response" == *'"sequence":1'* && "$response" == *'"state":"complete"'* ]]
# Unreachable fixtures back off from the configured 15 seconds to 30 seconds.
for _ in {1..45}; do
    response=$(docker exec "$container" /bin/bash -c "$history")
    [[ "$response" == *'"sequence":2'* && "$response" != *'"state":"checking"'* ]] && break
    sleep 1
done
[[ "$response" == *'"sequence":2'* && "$response" == *'"sequence":1'* ]]
docker stop --time 10 "$container" >/dev/null
docker start "$container" >/dev/null
ready
for _ in {1..50}; do
    response=$(docker exec "$container" /bin/bash -c "$history")
    [[ "$response" == *'"sequence":3'* && "$response" != *'"state":"checking"'* ]] && break
    sleep 0.2
done
[[ "$response" == *'200 OK'* && "$response" == *'"sequence":3'* ]]
[[ "$response" == *'"sequence":2'* && "$response" == *'"sequence":1'* ]]
[[ "$response" == *'"error":"tcp_unreachable"'* ]]
docker exec "$container" /bin/sh -c 'test "$(stat -c %a /data/filevault.sqlite3)" = 600; ! grep -aEq "fixture-user|192[.]0[.]2[.]1|example[.]invalid" /data/filevault.sqlite3'
printf '%s\n' 'Automatic periodic SQLite history survives process restart, retains successive checks, has owner-only permissions and stores no target or account identifiers'

# Cold restores recreate non-root private state as root:0644. Keep the actual
# credential, learned server identities and saved history across that boundary.
expected_credentials=$(docker exec "$container" sha256sum /data/credentials.json /data/ssh_known_hosts)
docker stop --time 10 "$container" >/dev/null
restored_volume="filevault-restored-${RANDOM}-${RANDOM}"
case $architecture in
    amd64) supervisor_image='ghcr.io/home-assistant/amd64-hassio-supervisor@sha256:f5f3728cf7a9a637485576c7588d209a1527fe9d6bb46f7326ef9aa629c55713' ;;
    arm64) supervisor_image='ghcr.io/home-assistant/aarch64-hassio-supervisor@sha256:0f606324063cd5e7e591fb71efb5214ff56a05514898e33e461757950abc2914' ;;
    *) echo 'Unsupported native restore architecture' >&2; exit 1 ;;
esac
docker volume create "$restored_volume" >/dev/null
# Use Supervisor's actual encrypted producer/extractor and copytree restore.
# Its FOWNER-dropped boundary recreates worker-owned files as root:0644.
docker run --rm --network none --read-only --cap-drop FOWNER \
    --tmpfs /tmp:rw,nosuid,nodev,noexec \
    --mount "type=volume,source=$volume,target=/source,readonly" \
    --mount "type=volume,source=$restored_volume,target=/restored" \
    --entrypoint python3 --interactive "$supervisor_image" - credentials.json ssh_known_hosts filevault.sqlite3 <<'PY'
import io
from pathlib import Path
import shutil
import sys
import tarfile
import tempfile
from securetar import SecureTarArchive, SecureTarFile, atomic_contents_add

password = "container-native-restore-only"
encrypted = io.BytesIO()
with SecureTarArchive(fileobj=encrypted, mode="w", password=password, create_version=3) as archive:
    with archive.create_tar("./app.tar.gz") as private:
        atomic_contents_add(private, Path("/source"), file_filter=lambda _: False, arcname="data")
encrypted.seek(0)
with tempfile.TemporaryDirectory() as extracted, tarfile.open(fileobj=encrypted, mode="r:") as outer:
    member = next(item for item in outer if item.name.endswith("app.tar.gz"))
    with SecureTarFile(fileobj=outer.extractfile(member), password=password, gzip=True) as private:
        private.extractall(path=extracted, filter="tar")
    shutil.copytree(Path(extracted, "data"), "/restored", symlinks=True, dirs_exist_ok=True)
for name in sys.argv[1:]:
    metadata = Path("/restored", name).stat()
    assert metadata.st_uid == 0 and metadata.st_mode & 0o777 == 0o644
print("Native restore reproduced root-owned0644 private files")
PY
docker rm "$container" >/dev/null
container=$(docker run --detach --read-only --network none --cap-drop FOWNER \
    --env SUPERVISOR_TOKEN=fixture-supervisor-token \
    --mount "type=volume,source=$restored_volume,target=/data" "$image" \
    --ingress-bind 127.0.0.1:8099 --ingress-peer 127.0.0.1)
ready
test "$(docker exec "$container" sha256sum /data/credentials.json /data/ssh_known_hosts)" = "$expected_credentials"
docker exec "$container" /bin/sh -ec '
    test "$(awk "\$1 == \"Uid:\" {print \$2}" /proc/1/status)" = 10001
    test "$(stat -c %a:%u:%g /data)" = 700:10001:10001
    for file in /data/options.json /data/credentials.json /data/ssh_known_hosts /data/filevault.sqlite3; do
        test "$(stat -c %a:%u:%g "$file")" = 600:10001:10001
    done
'
response=$(docker exec "$container" /bin/bash -c "$history")
[[ "$response" == *'200 OK'* && "$response" == *'"sequence":1'* && "$response" == *'"sequence":2'* ]]
printf '%s\n' 'Root-created cold restore retains pairing, server identities and durable SQLite history without FOWNER'
"$(dirname "${BASH_SOURCE[0]}")/private-data-smoke.sh" "$image"
