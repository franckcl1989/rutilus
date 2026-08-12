#!/usr/bin/env bash
#
# Rutilus macOS signing + notarization script — release pipeline (§5.4 of
# redfish-management-product-final-design.md, 1.0.0 release condition 17).
#
# Two modes:
#   sign      codesign with the Developer ID identity (hardened runtime,
#             timestamped, force re-sign) and verify the signature.
#   --notarize  submit the zip to Apple's notary service (--wait polls until
#             the notary finishes, 30m timeout), staple the ticket onto the
#             binary, and validate the staple.
#
# Usage:
#   scripts/sign-macos.sh <binary>                    # codesign + verify
#   scripts/sign-macos.sh --notarize <zip> <binary>   # notarize + staple
#
# Environment (secrets are passed ONLY through these variables; the script
# never echoes their values):
#   RUTILUS_MAC_CERT_ID        codesign identity (-s): Developer ID
#                              certificate name or SHA-256 fingerprint.
#                              Required in sign mode.
#   RUTILUS_NOTARY_KEY_ID      App Store Connect API key ID. Required in
#                              --notarize mode.
#   RUTILUS_NOTARY_KEY         Path to the App Store Connect API key (.p8
#                              file). Required in --notarize mode.
#   RUTILUS_NOTARY_TEAM_ID     Apple Developer team ID. Required in
#                              --notarize mode.
#
# Exit codes: 0 = success; 1 = missing env, missing file, or a
# codesign/notarytool/stapler failure.
set -euo pipefail

die() { echo "sign-macos.sh: ERROR: $*" >&2; exit 1; }
usage() { die "usage: scripts/sign-macos.sh <binary> | scripts/sign-macos.sh --notarize <zip> <binary>"; }

mode=sign
if [ "${1:-}" = "--notarize" ]; then
    mode=notarize
    shift
    [ "$#" -ge 2 ] || usage
    zipfile="$1"
    binary="$2"
else
    [ "$#" -ge 1 ] || usage
    binary="$1"
fi

[ -f "$binary" ] || die "binary not found: $binary"

case "$mode" in
    sign)
        [ -n "${RUTILUS_MAC_CERT_ID:-}" ] \
            || die "missing required environment variable: RUTILUS_MAC_CERT_ID (Developer ID certificate identity)"
        echo "sign-macos.sh: codesign: $binary"
        codesign --options runtime --timestamp --force --deep -s "$RUTILUS_MAC_CERT_ID" "$binary"
        codesign --verify --deep --strict --verbose=2 "$binary"
        echo "sign-macos.sh: OK: signed $binary"
        ;;
    notarize)
        [ -f "$zipfile" ] || die "zip not found: $zipfile"
        missing=""
        [ -n "${RUTILUS_NOTARY_KEY_ID:-}" ] || missing="$missing RUTILUS_NOTARY_KEY_ID"
        [ -n "${RUTILUS_NOTARY_KEY:-}" ] || missing="$missing RUTILUS_NOTARY_KEY"
        [ -n "${RUTILUS_NOTARY_TEAM_ID:-}" ] || missing="$missing RUTILUS_NOTARY_TEAM_ID"
        [ -z "$missing" ] \
            || die "missing required environment variable(s):$missing (App Store Connect API credentials for notarization)"
        echo "sign-macos.sh: notarytool submit (--wait polls; 30m timeout): $zipfile"
        xcrun notarytool submit "$zipfile" \
            --key-id "$RUTILUS_NOTARY_KEY_ID" \
            --key "$RUTILUS_NOTARY_KEY" \
            --team-id "$RUTILUS_NOTARY_TEAM_ID" \
            --wait --timeout 30m
        echo "sign-macos.sh: stapler staple: $binary"
        xcrun stapler staple "$binary"
        xcrun stapler validate "$binary"
        echo "sign-macos.sh: OK: notarized and stapled $binary"
        ;;
esac
