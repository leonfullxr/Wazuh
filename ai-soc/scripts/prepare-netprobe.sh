#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd -P)"
source_file="$repo_root/scripts/netprobe.c"
cache_dir="$repo_root/build/tool-cache"
output="$cache_dir/netprobe-static"
source_sha256=7f0fc5bf04c057fbb94d3667ad0f26e1fcc9ae92cd20c7bdf4f89f6f447cfb57
binary_sha256=04fc06dba0caa8ef4060a0c6ce9fe6314c7b9d039d8b2c292c5f99fc10c02ae5
compiler_version='gcc (Debian 12.2.0-14+deb12u1) 12.2.0'

actual_source_sha256="$(sha256sum "$source_file" | cut -d ' ' -f 1)"
if [[ "$actual_source_sha256" != "$source_sha256" ]]; then
    echo "netprobe source digest mismatch: $actual_source_sha256" >&2
    exit 78
fi
if [[ "$(/usr/bin/gcc --version | head -n 1)" != "$compiler_version" ]]; then
    echo "netprobe requires $compiler_version" >&2
    exit 78
fi

mkdir -p "$cache_dir"
temporary="$cache_dir/.netprobe-static.$$"
trap 'rm -f "$temporary"' EXIT
/usr/bin/gcc -static -no-pie -O2 -Wall -Wextra -Werror -fno-ident \
    -Wl,--build-id=none -o "$temporary" "$source_file"
actual_binary_sha256="$(sha256sum "$temporary" | cut -d ' ' -f 1)"
if [[ "$actual_binary_sha256" != "$binary_sha256" ]]; then
    echo "netprobe binary digest mismatch: $actual_binary_sha256" >&2
    exit 78
fi
chmod 0755 "$temporary"
mv -f "$temporary" "$output"
trap - EXIT
printf '%s  %s\n' "$binary_sha256" "$output"
