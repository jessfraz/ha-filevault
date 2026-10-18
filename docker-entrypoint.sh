#!/bin/sh
set -eu
# Debian dash supports the core-file limit; keep crash dumps disabled.
# shellcheck disable=SC3045
ulimit -c 0
if [ "$(id -u)" -eq 0 ]; then
    chown filevault:filevault /data
    if [ -f /data/options.json ]; then
        chown filevault:filevault /data/options.json
    fi
    if [ -f /data/credentials.json ]; then
        chown -h filevault:filevault /data/credentials.json
    fi
    exec gosu filevault "$0" "$@"
fi
umask 077
if [ -f /data/options.json ]; then
    set -- --options /data/options.json "$@"
fi
if [ "${FILEVAULT_ENABLE_INGRESS:-false}" = true ]; then
    export FILEVAULT_INGRESS_BIND=0.0.0.0:8099
    export FILEVAULT_INGRESS_PEER=172.30.32.2
    export FILEVAULT_BIND=0.0.0.0:8080
fi
exec filevault "$@"
