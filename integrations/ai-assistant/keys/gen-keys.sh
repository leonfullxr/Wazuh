#!/usr/bin/env bash
# Per-tenant JWT signing keypair (D30). The PRIVATE key is mounted ONLY into the
# auth shim. The tool service and the indexer get the public key and can only verify.
set -euo pipefail
cd "$(dirname "$0")"

if [[ -f jwt-private.pem ]]; then
  echo "keys already exist, refusing to overwrite (delete them first to rotate)"
  exit 0
fi

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out jwt-private.pem
openssl pkey -in jwt-private.pem -pubout -out jwt-public.pem
chmod 600 jwt-private.pem
echo "wrote keys/jwt-private.pem (shim only) and keys/jwt-public.pem (verifiers)"
