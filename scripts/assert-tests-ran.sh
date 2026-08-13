#!/usr/bin/env bash
#
# Rutilus CI test-ran assertion (W6-1, 2026-08-13).
#
# Runs `cargo test` with the given arguments and fails the step unless the
# number of tests that actually ran and passed is >= <min-passed>. This is
# the mechanical ran-assertion for the test-shaped CI gates: without it a
# gate goes silently green when the test file is deleted, every test is
# marked #[ignore], or the tests are emptied out of the build via
# #[cfg(any())]. Deleting the file is the only one of the three that plain
# `cargo test` already catches (missing test target); #[ignore] and
# cfg-emptied tests still "succeed" with 0 passed.
#
# Origin: W6-1 of the 2026-08-13 CI-surface review — the secret-leak gate
# (.github/workflows/ci.yml "Secret leak gate") and the migration gate
# ("Migration test") had no assertion that their tests actually ran. The
# pinned minimums live next to each gate in .github/workflows/ci.yml; they
# were measured on master (2026-08-12 gate re-run, documented in
# docs/release-readiness.md §五 门禁复跑: security 门禁 8, migration 38).
#
# NOTE: the min-passed case below keeps `[1-9]` as its own alternative —
# the double-bracket glob `[1-9][0-9]*` alone rejects single-digit values
# in bash case (CI hit this: pin "8" was refused), and single digits are
# legitimate pins. Do not merge the three patterns back into two.
#
# Usage:
#   scripts/assert-tests-ran.sh <min-passed> [cargo test args...]
#
# `cargo test` is implicit: the args are exactly what the gate step used to
# pass to it (e.g. `--locked -p rutilus-security --test secret_leak_gate`).
#
# The count is the sum of the `test result: ok. N passed; ...` lines libtest
# prints per test binary (one per binary; doc-test harnesses included). A
# cargo error (missing test target, compile error, failing test) is
# propagated as the step's failure; a run with zero passing tests — no
# `test result: ok.` line at all, or a sum below the pin — fails the
# assertion.
#
# Exit codes: 0 = >= min-passed tests passed; 1 = fewer passed (or no
# `test result` line seen); otherwise cargo's own exit code.
set -uo pipefail
# (no `-e` by design: cargo's exit status is captured below so its output
# can be echoed to the log before the step fails — an `-e` abort would
# swallow the test output that the failure diagnosis needs)

die() { echo "assert-tests-ran.sh: ERROR: $*" >&2; exit 1; }

[ "$#" -ge 2 ] || die "usage: scripts/assert-tests-ran.sh <min-passed> [cargo test args...]"
min="$1"
shift
case "$min" in
    0 | [1-9] | [1-9][0-9]*) ;;
    *) die "min-passed must be a non-negative integer without a leading zero (bash arithmetic parses leading zeros as octal), got: $min" ;;
esac

out="$(cargo test "$@" 2>&1)"
status=$?
printf '%s\n' "$out"
[ "$status" -eq 0 ] || exit "$status"

# Sum the per-binary passed counts; an empty match (no `test result: ok.`
# line — e.g. zero test binaries ran) sums to 0 and fails below.
passed="$(printf '%s\n' "$out" | sed -n 's/^test result: ok\. \([0-9][0-9]*\) passed.*/\1/p' | awk '{s += $1} END {print s + 0}')"

if [ "$passed" -lt "$min" ]; then
    die "expected >= $min tests to pass, only $passed did — a test file was deleted, #[ignore]d, or cfg-emptied?"
fi
echo "assert-tests-ran.sh: $passed tests passed (pinned minimum: $min)"
