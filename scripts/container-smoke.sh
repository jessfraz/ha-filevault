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
options='{"allowed_user_ids":["fixture-user"],"frontend_origin":"","status_token":"","auto_pairing":true,"ssh_recovery":{"enabled":false}}'
container=$(docker run --detach --read-only --network none --user 10001:10001 \
    --tmpfs /data:rw,noexec,nosuid,nodev,size=1m,uid=10001,gid=10001,mode=0700 \
    --env SUPERVISOR_TOKEN=supervisor-only-dummy-token --entrypoint /bin/sh \
    "$image" -c 'printf "%s" "$1" > /data/options.json; exec /usr/local/bin/docker-entrypoint.sh --ingress-bind 127.0.0.1:8099 --ingress-peer 127.0.0.1' sh "$options")
probe='exec 3<>/dev/tcp/127.0.0.1/8099; printf "GET /v1/status HTTP/1.1\r\nHost: localhost\r\nX-Remote-User-Id: fixture-user\r\nConnection: close\r\n\r\n" >&3; cat <&3'
response=
for _ in {1..20}; do
    if response=$(docker exec "$container" /bin/bash -c "$probe" 2>/dev/null); then
        break
    fi
    sleep 0.2
done
[[ "$response" == *'200 OK'* ]]
[[ "$response" == *'"state":"unknown"'* ]]
[[ "$response" == *'"transport_ready":false'* ]]
docker exec "$container" /bin/sh -c 'test "$(id -u)" -eq 10001; test "$(stat -c %a /data/credentials.json)" = 600'
printf '%s\n' 'App options, automatic credential bootstrap, authenticated status and disabled recovery passed'
