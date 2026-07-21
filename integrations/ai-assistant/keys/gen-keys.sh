#!/usr/bin/env bash
# Per-tenant JWT signing keypair (D30). The PRIVATE key is mounted ONLY into the
# auth shim. The tool service and the indexer get the public key and can only verify.
#
# Usage: ./keys/gen-keys.sh [output-dir]
#   default output-dir is the keys/ directory containing this script.
set -euo pipefail
OUT_DIR="$(cd "$(dirname "$0")" && pwd)"
if [[ $# -ge 1 ]]; then
  mkdir -p "$1"
  OUT_DIR="$(cd "$1" && pwd)"
fi

if [[ -f "$OUT_DIR/jwt-private.pem" ]]; then
  echo "keys already exist in $OUT_DIR, refusing to overwrite (delete first to rotate)"
  exit 0
fi

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$OUT_DIR/jwt-private.pem"
openssl pkey -in "$OUT_DIR/jwt-private.pem" -pubout -out "$OUT_DIR/jwt-public.pem"
chmod 600 "$OUT_DIR/jwt-private.pem"
echo "wrote $OUT_DIR/jwt-private.pem (shim only) and $OUT_DIR/jwt-public.pem (verifiers)"
