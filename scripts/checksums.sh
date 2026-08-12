#!/usr/bin/env bash
#
# Rutilus SHA-256 manifest generator — release pipeline (§5.4: 生成 SHA-256,
# 1.0.0 release condition 17). Emits the standard `sha256sum` format
# "<lowercase-hex>  <basename>" so users verify with `sha256sum -c`.
#
# Usage:
#   scripts/checksums.sh [-o SHA256SUMS] <file> [<file> ...]
#
# Options:
#   -o <output>   Manifest path (default: SHA256SUMS in the working dir).
#
# Writes atomically (tmp file + rename), so a failed run never leaves a
# truncated manifest. Uses sha256sum when available, else falls back to
# `shasum -a 256` (macOS). Runs on the GitHub Actions Windows runner via
# git-bash as well (POSIX relative paths, e.g. release/* — git-bash mangles
# Windows absolute paths through MSYS conversion, so on a native Windows
# host use scripts/checksums.ps1 instead).
#
# Exit codes: 0 = manifest written; 1 = missing input file or no hash tool.
set -euo pipefail

die() { echo "checksums.sh: ERROR: $*" >&2; exit 1; }

output="SHA256SUMS"
while getopts "o:" opt; do
    case "$opt" in
        o) output="$OPTARG" ;;
        *) die "usage: scripts/checksums.sh [-o SHA256SUMS] <file> [<file> ...]" ;;
    esac
done
shift $((OPTIND - 1))
[ "$#" -ge 1 ] || die "usage: scripts/checksums.sh [-o SHA256SUMS] <file> [<file> ...]"

if command -v sha256sum >/dev/null 2>&1; then
    hash_of() { sha256sum "$1" | awk '{print $1}'; }
else
    command -v shasum >/dev/null 2>&1 || die "neither sha256sum nor shasum found in PATH"
    hash_of() { shasum -a 256 "$1" | awk '{print $1}'; }
fi

tmp="${output}.tmp.$$"
trap 'rm -f "$tmp"' EXIT
: > "$tmp"
for file in "$@"; do
    [ -f "$file" ] || die "file not found: $file"
    name="${file##*/}"
    # Also tolerate Windows-style separators for git-bash callers.
    case "$name" in *\\*) name="${name##*\\}" ;; esac
    printf '%s  %s\n' "$(hash_of "$file")" "$name" >> "$tmp"
done
mv "$tmp" "$output"
trap - EXIT
echo "checksums.sh: wrote $output ($# files)"
