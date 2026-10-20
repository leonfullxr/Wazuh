#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd -P)"
developer_home="$HOME"
private_root="$repo_root/build/private"
mkdir -p "$private_root/home" "$private_root/tmp" "$repo_root/build/evidence" "$repo_root/build/tool-cache"
git -C "$repo_root" ls-files -z > "$private_root/tracked-files"
cc -shared -fPIC -O2 -Wall -Wextra -Werror \
    -o "$private_root/libnetdeny.so" "$repo_root/scripts/netdeny.c" -ldl
if [[ ! -x /usr/bin/bwrap ]]; then
    echo "offline acceptance requires bubblewrap with user and network namespaces" >&2
    exit 78
fi
"$repo_root/scripts/prepare-netprobe.sh"
/usr/bin/bwrap --unshare-net --ro-bind / / --dev /dev --proc /proc true
export HOME="$private_root/home"
export AI_SOC_TRACKED_FILES_FILE="$private_root/tracked-files"
export TMPDIR="$private_root/tmp"
export AWS_CONFIG_FILE=/dev/null
export AWS_SHARED_CREDENTIALS_FILE=/dev/null
export AWS_EC2_METADATA_DISABLED=true
export AWS_DEFAULT_REGION=us-east-1
export AWS_REGION=us-east-1
export TZ=UTC
export LC_ALL=C.UTF-8
export PYTHONHASHSEED=0
export SOC_MODE=fixture
export SOC_ANCHOR=2026-09-30T12:00:00Z
export TF_PLUGIN_CACHE_DIR="$repo_root/build/tool-cache/terraform/plugins"
export TF_CLI_CONFIG_FILE="$repo_root/build/tool-cache/terraform.tfrc"
export LD_PRELOAD="$private_root/libnetdeny.so${LD_PRELOAD:+:$LD_PRELOAD}"
unset AWS_PROFILE AWS_WEB_IDENTITY_TOKEN_FILE AWS_CONTAINER_CREDENTIALS_RELATIVE_URI
unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
cd "$repo_root"
if [[ "$repo_root" != "$developer_home"/* ]]; then
    echo "offline runner requires the checkout below the home directory" >&2
    exit 78
fi
relative_repo="${repo_root#"$developer_home"/}"
IFS=/ read -r -a repo_parts <<< "$relative_repo"
bwrap_args=(
    --unshare-net
    --ro-bind / /
    --tmpfs "$developer_home"
    --dir "$developer_home/.local"
    --ro-bind "$developer_home/.local" "$developer_home/.local"
    --tmpfs /tmp
    --tmpfs /run/user
    --dev /dev
    --proc /proc
)
parent_path="$developer_home"
for ((part_index = 0; part_index < ${#repo_parts[@]} - 1; part_index++)); do
    parent_path="$parent_path/${repo_parts[$part_index]}"
    bwrap_args+=(--dir "$parent_path")
done
bwrap_args+=(--dir "$repo_root" --bind "$repo_root" "$repo_root" --chdir "$repo_root")
tmpfs_scratch="${SOC_B6_TMPFS_SCRATCH_ROOT:-}"
if [[ -n "$tmpfs_scratch" ]]; then
    if [[ ! "$tmpfs_scratch" =~ ^/dev/shm/soc-image-repro-[0-9]{8}T[0-9]{12}Z$ ]] \
        || [[ ! -d "$tmpfs_scratch" || -L "$tmpfs_scratch" ]]; then
        echo "offline runner rejected an invalid tmpfs scratch namespace" >&2
        exit 78
    fi
    bwrap_args+=(--bind "$tmpfs_scratch" "$tmpfs_scratch")
fi
exec /usr/bin/bwrap "${bwrap_args[@]}" "$@"
