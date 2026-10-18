set shell := ["bash", "-euo", "pipefail", "-c"]

default: check

public-tree:
    ./scripts/check-public-tree

versions:
    ./scripts/check-release-version

rust:
    cargo fmt --check
    cargo clippy --locked --all --benches --tests --examples --all-features -- -D warnings
    cargo test --locked --all-features

ha:
    uv sync --frozen
    uv run --frozen ruff check custom_components tests_ha scripts/build-release-artifacts
    uv run --frozen ruff format --check custom_components tests_ha scripts/build-release-artifacts
    uv run --frozen ty check --project . --python .venv --python-version 3.14 --error-on-warning custom_components tests_ha scripts/build-release-artifacts
    uv run --frozen pytest tests_ha

web:
    node --check web/app.js
    node tests_web/policy.mjs
    node tests_web/recovery.mjs
    node tests_web/app.mjs

check: public-tree versions rust ha web

test: check

security:
    cargo deny check advisories licenses sources

openapi:
    cargo run --locked -- --openapi openapi/api.json

container:
    docker build --tag ha-filevault:smoke .
    ./scripts/container-smoke.sh ha-filevault:smoke "$(docker image inspect ha-filevault:smoke --format '{{{{.Architecture}}')"
