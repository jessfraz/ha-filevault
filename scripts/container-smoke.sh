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
cleanup() {
    if [[ -n "$container" ]]; then
        docker stop --time 5 "$container" >/dev/null 2>&1 || true
        docker rm "$container" >/dev/null 2>&1 || true
    fi
    if [[ -n "$volume" ]]; then
        docker volume rm "$volume" >/dev/null 2>&1 || true
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
options='{"allowed_user_ids":["fixture-user"],"frontend_origin":"https://ha.example.invalid","mac":{"host":"192.0.2.1","port":22,"username":"fixture-user","tailscale_host":""}}'
container=$(docker run --detach --read-only --network none \
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
