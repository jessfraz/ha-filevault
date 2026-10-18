#!/usr/bin/env bash
set -euo pipefail
image=${1:?image required}
architecture=${2:?architecture required}
actual=$(docker image inspect "$image" --format '{{.Architecture}}')
test "$actual" = "$architecture"
docker run --rm --read-only --network none --user 10001:10001 "$image" --version

# Exercise actual HA options and credential bootstrap on ephemeral RAM only.
container=
cleanup() {
    if [[ -n "$container" ]]; then
        docker stop --time 5 "$container" >/dev/null 2>&1 || true
        docker rm "$container" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT
options='{"allowed_user_ids":["fixture-user"],"frontend_origin":"https://ha.example.invalid","status_token":"","auto_pairing":true,"ssh_recovery":{"enabled":true,"host":"192.0.2.1","port":22,"username":"fixture-user","preboot_public_key":"","runtime_public_key":"","manual_enrollment_verified":false}}'
container=$(docker run --detach --read-only --network none --user 10001:10001 \
    --tmpfs /data:rw,noexec,nosuid,nodev,size=1m,uid=10001,gid=10001,mode=0700 \
    --env SUPERVISOR_TOKEN=supervisor-only-dummy-token --entrypoint /bin/sh \
    "$image" -c 'printf "%s" "$1" > /data/options.json; sha256sum /data/options.json > /data/options.sha256; exec /usr/local/bin/docker-entrypoint.sh --ingress-bind 127.0.0.1:8099 --ingress-peer 127.0.0.1' sh "$options")
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
[[ "$response" == *'Automatic phase detection is incomplete or invalid.'* ]]
docker exec "$container" /bin/sh -c 'test "$(id -u)" -eq 10001; test "$(stat -c %a /data/credentials.json)" = 600; test "$(stat -c %a /data/ssh_known_hosts)" = 600; sha256sum --status --check /data/options.sha256'
printf '%s\n' 'Incomplete phase setup keeps authenticated UI and manual SSH available; private bootstrap files and original options preserved'
