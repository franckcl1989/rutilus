#!/usr/bin/env bash
#
# Rutilus Linux independent signing script — release pipeline (§5.4 of
# redfish-management-product-final-design.md, 1.0.0 release condition 17).
#
# Tool choice: minisign (https://jedisct1.github.io/minisign/).
# Why minisign rather than gpg for "独立签名" (independent signing):
#   - Semantics: minisign emits one detached signature file per artifact
#     (<file> -> <file>.minisig), verified with a single published public
#     key — exactly the "independent signing + public-key publication path"
#     §5.4 and docs/release-readiness.md §三-C describe. gpg's
#     keyring/trust-web model is heavyweight for this and drags in its own
#     key-management story.
#   - Automation: the secret key is a single file and its passphrase flows
#     through minisign's native MINISIGN_PASSWORD environment variable
#     (exported here from RUTILUS_LINUX_SIGN_PASSWORD) — fully
#     non-interactive in CI, no keyring import, no passphrase on the command
#     line. gpg in CI needs --batch keyring import and a loopback
#     pinentry/fd dance.
#   - Verification UX: `minisign -Vm <file> -P <pubkey>.minisign` — one
#     command, with the public key file shipped next to SHA256SUMS.
#
# Usage:
#   scripts/sign-linux.sh <file> [<file> ...]
#
# Environment (secrets are passed ONLY through these variables; the script
# never echoes their values):
#   RUTILUS_LINUX_SIGN_KEY        Path to the minisign secret key. Required.
#   RUTILUS_LINUX_SIGN_PASSWORD   Key passphrase (optional). Exported to
#                                 minisign's MINISIGN_PASSWORD channel, which
#                                 keeps it off the command line and out of
#                                 the log. Omit only for an unencrypted key.
#
# Produces <file>.minisig next to each file and verifies it against the
# public half embedded in the secret key file (no decryption involved).
#
# Exit codes: 0 = all files signed and verified; 1 = missing key env, a file
# missing, minisign not installed, or a sign/verify failure.
set -euo pipefail

die() { echo "sign-linux.sh: ERROR: $*" >&2; exit 1; }

[ "$#" -ge 1 ] || die "usage: scripts/sign-linux.sh <file> [<file> ...]"
[ -n "${RUTILUS_LINUX_SIGN_KEY:-}" ] \
    || die "missing required environment variable: RUTILUS_LINUX_SIGN_KEY (path to the minisign secret key)"
[ -f "$RUTILUS_LINUX_SIGN_KEY" ] || die "sign key not found: $RUTILUS_LINUX_SIGN_KEY"
command -v minisign >/dev/null 2>&1 \
    || die "minisign not found in PATH (CI: sudo apt-get install -y minisign; local: brew install minisign, see https://jedisct1.github.io/minisign/)"

# The passphrase never touches the command line or the log: minisign reads
# MINISIGN_PASSWORD natively. Unset first so a stale value cannot leak in.
unset MINISIGN_PASSWORD
if [ -n "${RUTILUS_LINUX_SIGN_PASSWORD:-}" ]; then
    export MINISIGN_PASSWORD="$RUTILUS_LINUX_SIGN_PASSWORD"
fi

for file in "$@"; do
    [ -f "$file" ] || die "file not found: $file"
    echo "sign-linux.sh: signing: $file"
    minisign -S -m "$file" -s "$RUTILUS_LINUX_SIGN_KEY"
    # -V with -s verifies against the public half embedded in the key file
    # (public-half read only; no passphrase required).
    minisign -V -m "$file" -s "$RUTILUS_LINUX_SIGN_KEY" >/dev/null
    echo "sign-linux.sh: OK: $file -> $file.minisig"
done
echo "sign-linux.sh: all files signed"
