#!/usr/bin/env bash
# otlp_syslog_follow.sh
# Follows a JSON log (e.g. OpenTelemetry OTLP output), extracts the embedded
# syslog line from any "stringValue" field, strips the <PRI> prefix and
# backslashes, and appends the clean line to an output file that the Wazuh
# agent can tail as plain syslog.
#
# Usage:
#   otlp_syslog_follow.sh [/path/to/input.log] [/path/to/output.log]
# Defaults:
#   input : /var/log/otlp/syslog.log
#   output: /var/log/otlp/syslog_extracted.log

set -euo pipefail

SRC="${1:-/var/log/otlp/syslog.log}"
DST="${2:-/var/log/otlp/syslog_extracted.log}"

mkdir -p "$(dirname "$DST")"
touch "$DST"  # ensure it exists (helps Wazuh start tailing early)

# Follow from the end (-n 0) and across rotations (-F).
# stdbuf/jq --unbuffered ensures near-instant writes to $DST.
exec tail -n 0 -F "$SRC" \
  | stdbuf -oL -eL jq -r --unbuffered '
      .. | objects | .stringValue? // empty
      | sub("^<[^>]+>"; "")   # drop <PRI>
      | gsub("\\\\"; "")      # remove backslashes
    ' >> "$DST"
