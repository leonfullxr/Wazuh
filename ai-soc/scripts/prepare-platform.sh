#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd -P)"
cache="$repo_root/build/tool-cache"
mkdir -p "$cache/terraform" "$cache/tflint" "$cache/trivy" "$cache/node-v22.23.3" \
    "$cache/docker-compose-v5.5.1" "$cache/docker-buildx-v0.37.1" "$cache/terraform/plugins"
command -v curl >/dev/null
command -v unzip >/dev/null
command -v tar >/dev/null
command -v sha256sum >/dev/null

fetch() {
    local url="$1" destination="$2" temporary
    if [[ -f "$destination" ]]; then
        return
    fi
    temporary="$destination.download"
    curl --fail --location --silent --show-error "$url" --output "$temporary"
    mv "$temporary" "$destination"
}

verify() {
    local expected="$1" path="$2" observed
    observed="$(sha256sum "$path" | cut -d ' ' -f 1)"
    if [[ "$observed" != "$expected" ]]; then
        echo "SHA-256 mismatch for $path: expected $expected, observed $observed" >&2
        exit 1
    fi
}

terraform_archive="$cache/terraform_1.16.5_linux_amd64.zip"
fetch "https://releases.hashicorp.com/terraform/1.16.5/terraform_1.16.5_linux_amd64.zip" "$terraform_archive"
verify 2bc2fcfff033265c9e02ca0351f01794eb122f62a9b2a49a3294b9e49eaab5e4 "$terraform_archive"
unzip -oq "$terraform_archive" terraform -d "$cache/terraform"

tflint_archive="$cache/tflint_linux_amd64.zip"
fetch "https://github.com/terraform-linters/tflint/releases/download/v0.64.0/tflint_linux_amd64.zip" "$tflint_archive"
verify cca9d13e2e1d7a2c627af60ff899a3c9b74212899416aeb96ec764d2ef954537 "$tflint_archive"
unzip -oq "$tflint_archive" tflint -d "$cache/tflint"

trivy_archive="$cache/trivy_0.74.0_Linux-64bit.tar.gz"
fetch "https://github.com/aquasecurity/trivy/releases/download/v0.74.0/trivy_0.74.0_Linux-64bit.tar.gz" "$trivy_archive"
verify 2ae6fe3ee734b7fdf11335663e18c75ea12dccc76062f09f164a3b0f8be4371a "$trivy_archive"
tar -xzf "$trivy_archive" -C "$cache/trivy" trivy

node_archive="$cache/node-v22.23.3/node-v22.23.3-linux-x64.tar.xz"
node_checksums="$cache/node-v22.23.3/SHASUMS256.txt"
fetch https://nodejs.org/download/release/v22.23.3/SHASUMS256.txt "$node_checksums"
verify 4fe99a2ba9d552a6f51c13ed68fb11104cfa5df601aec616be689253a8139e7a "$node_checksums"
fetch https://nodejs.org/download/release/v22.23.3/node-v22.23.3-linux-x64.tar.xz "$node_archive"
verify df450af89261115ef9f9e3830c3eeb2cc9213b63c720b1af623cb5dcbe2e02de "$node_archive"
mkdir -p "$cache/node-v22.23.3/extracted"
tar -xJf "$node_archive" --strip-components=1 -C "$cache/node-v22.23.3/extracted"

mkdir -p "$repo_root/build/tool-cache/b5-ui-sync" "$repo_root/build/tool-cache/playwright"
cp "$repo_root/dev/pinned-inputs/b5-ui-package.json" "$repo_root/build/b5-ui-package.json"
cp "$repo_root/ui/package-lock.json" "$repo_root/build/b5-ui-package-lock.json"
cp "$repo_root/ui/package-lock.json" "$repo_root/build/tool-cache/b5-ui-sync/package-lock.json"
cp "$repo_root/dev/pinned-inputs/b5-ui-package.json" \
    "$repo_root/build/tool-cache/b5-ui-sync/package.json"
cp "$repo_root/dev/pinned-inputs/b6-toolchain.lock.json" "$repo_root/build/toolchain.lock.json"
cp "$repo_root/infra/.terraform.lock.hcl" "$repo_root/build/b6-provider.lock.hcl"

node="$cache/node-v22.23.3/extracted/bin/node"
npm="$cache/node-v22.23.3/extracted/bin/npm"
PLAYWRIGHT_BROWSERS_PATH="$repo_root/build/tool-cache/playwright" \
    "$node" "$npm" ci --prefix "$repo_root/build/tool-cache/b5-ui-sync" \
    --ignore-scripts --no-audit --no-fund
PLAYWRIGHT_BROWSERS_PATH="$repo_root/build/tool-cache/playwright" \
    "$node" "$cache/b5-ui-sync/node_modules/@playwright/test/cli.js" install chromium

compose="$cache/docker-compose-v5.5.1/docker-compose"
fetch https://github.com/docker/compose/releases/download/v5.5.1/docker-compose-linux-x86_64 "$compose"
verify db1889184726840f75c4f9c001048430d4f25b3be3cb084d3ddd762bc0aed576 "$compose"
chmod 0555 "$compose"

buildx="$cache/docker-buildx-v0.37.1/buildx"
fetch https://github.com/docker/buildx/releases/download/v0.37.1/buildx-v0.37.1.linux-amd64 "$buildx"
verify 9447199cdb435f25880548343c128a4b6650e8891ee598905d8d29d39a8e359b "$buildx"
chmod 0555 "$buildx"

terraform="$cache/terraform/terraform"
export TF_PLUGIN_CACHE_DIR="$cache/terraform/plugins"
if [[ ! -f "$repo_root/infra/.terraform.lock.hcl" ]]; then
    "$terraform" -chdir="$repo_root/infra" init -backend=false -input=false
else
    "$terraform" -chdir="$repo_root/infra" init -backend=false -input=false -lockfile=readonly
fi
"$terraform" -chdir="$repo_root/infra" providers mirror -platform=linux_amd64 \
    "$cache/terraform/mirror"
cat >"$cache/terraform.tfrc" <<EOF
provider_installation {
  filesystem_mirror {
    path    = "$cache/terraform/mirror"
    include = ["registry.terraform.io/hashicorp/aws"]
  }
}
EOF
TF_CLI_CONFIG_FILE="$cache/terraform.tfrc" \
    "$terraform" -chdir="$repo_root/infra" init -backend=false -input=false -lockfile=readonly

trivy="$cache/trivy/trivy"
trivy_database_repository="$(uv run --locked --all-groups python -c 'import json; print(json.load(open("dev/toolchain.lock.json"))["preparation"]["scanner_database_repository"])')"
"$trivy" image --cache-dir "$cache/trivy-cache" --db-repository "$trivy_database_repository" \
    --download-db-only

"$terraform" version | head -1
"$cache/tflint/tflint" --version
"$trivy" --version | head -2
"$cache/docker-compose-v5.5.1/docker-compose" --version
"$cache/docker-buildx-v0.37.1/buildx" version
"$cache/node-v22.23.3/extracted/bin/node" --version

uv run --locked --all-groups python - "$repo_root" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

root = Path(sys.argv[1])
lock_path = root / "dev/toolchain.lock.json"
lock = json.loads(lock_path.read_text())
provider_lock = root / "infra/.terraform.lock.hcl"
scanner_database = root / "build/tool-cache/trivy-cache/db/trivy.db"
if not provider_lock.is_file() or not scanner_database.is_file():
    raise SystemExit("provider lock or Trivy database is missing")
sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
prep = lock["preparation"]
if sha(provider_lock) != prep["provider_lock_sha256"]:
    raise SystemExit("Terraform provider lock differs from the selected platform input")
if sha(scanner_database) != prep["scanner_database_digest"]:
    raise SystemExit("Trivy database bytes differ from the selected platform input")
evidence = {
    "schema_version": "1",
    "toolchain_lock_sha256": sha(lock_path),
    "provider_lock_sha256": prep["provider_lock_sha256"],
    "scanner_database_sha256": prep["scanner_database_digest"],
    "images": [item["reference"] for item in lock["images"]],
}
(root / "build/tool-cache/preparation.json").write_text(
    json.dumps(evidence, indent=2, sort_keys=True) + "\n"
)
print(json.dumps(evidence, sort_keys=True))
PY
