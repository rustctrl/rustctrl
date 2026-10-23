#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

smoke_project="rustctrl-smoke-$$"
smoke_dir="$(mktemp -d)"
export RUSTCTRL_LISTEN_ADDRESS=127.0.0.1
export RUSTCTRL_PORT="${RUSTCTRL_SMOKE_PORT:-19876}"
export RUSTCTRL_SERVER_NAME=localhost
export RUSTCTRL_SERVER_IP=127.0.0.1
export RUSTCTRL_SERVER_ENDPOINT="https://localhost:${RUSTCTRL_PORT}"
compose() { docker compose -p "$smoke_project" --profile tools "$@"; }
cleanup() {
  compose down --volumes --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$smoke_dir"
}
trap cleanup EXIT
if [[ "${RUSTCTRL_SKIP_IMAGE_BUILD:-0}" != 1 ]]; then
  compose build server
fi
compose run --rm pki-init
compose up -d server
wait_for_health() {
  for attempt in {1..60}; do
    if compose exec -T server rustctrl-server healthcheck --tls-dir /tls > "$smoke_dir/health" 2>/dev/null; then
      cat "$smoke_dir/health"
      return 0
    fi
    sleep 1
  done
  compose logs server
  return 1
}
wait_for_health
compose run --rm -T --entrypoint tar pki-init -C /pki/clients -cf - agent > "$smoke_dir/agent.tar"
tar -xf "$smoke_dir/agent.tar" -C "$smoke_dir"
cargo run --locked -p rustctrl_agent -- console --config "$smoke_dir/agent/config.toml" --once
compose restart server
wait_for_health
grep -q 'registered_devices=1' "$smoke_dir/health"
echo "Compose foundation smoke test passed."
