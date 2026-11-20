#!/bin/sh
set -eu
runner_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
server_dir=$(CDPATH= cd -- "$runner_dir/../.." && pwd)
work_dir=$(mktemp -d "${TMPDIR:-/tmp}/wazuh-mcp-app-client.XXXXXXXX")
trap 'rm -rf "$work_dir"' EXIT HUP INT TERM
cp "$runner_dir"/package.json "$runner_dir"/run.mjs "$runner_dir"/host-entry.js "$runner_dir"/fixture_server.py "$work_dir"/
npm install --prefix "$work_dir" --no-package-lock --ignore-scripts --no-audit --no-fund
MCP_SERVER_DIR="$server_dir" node "$work_dir/run.mjs"
