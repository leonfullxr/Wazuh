#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
  echo "Usage: $0 <confluence-audit-export.json> [output.ndjson]" >&2
  exit 2
fi

command -v jq >/dev/null 2>&1 || {
  echo "Error: jq is required." >&2
  exit 1
}

input_file=$1
[[ -f "$input_file" ]] || {
  echo "Error: input file does not exist: $input_file" >&2
  exit 1
}

base_name=$(basename "$input_file" .json)
output_file=${2:-"$(dirname "$input_file")/converted_${base_name}.ndjson"}
output_dir=$(dirname "$output_file")
mkdir -p "$output_dir"

tmp_file=$(mktemp "${output_dir}/.confluence-audit.XXXXXX")
trap 'rm -f "$tmp_file"' EXIT

jq -ce '.results[]' "$input_file" >"$tmp_file"
chmod 0640 "$tmp_file"
mv -f "$tmp_file" "$output_file"
trap - EXIT

echo "Wrote $(wc -l <"$output_file") Confluence audit records to $output_file"