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
# were measured on master (2026-08-12 gate re-run; re-measured 2026-08-13
# wave-four V4I-3: security 门禁 10, migration 50 — documented in
# docs/release-readiness.md §五 门禁复跑).
#
# NOTE: the min-passed case below keeps `[1-9]` as its own alternative —
# the double-bracket glob `[1-9][0-9]*` alone rejects single-digit values
# in bash case (CI hit this: pin "8" was refused), and single digits are
# legitimate pins. Do not merge the three patterns back into two.
#
# Usage:
#   scripts/assert-tests-ran.sh <min-passed> [--expect-tests name1,name2,...] [cargo test args...]
#   (each expected name is a Rust identifier, optionally `::`-qualified:
#    `foo` matches `module::tests::foo` by suffix, `module::tests::foo` is exact)
#
# `cargo test` is implicit: the args are exactly what the gate step used to
# pass to it (e.g. `--locked -p rutilus-security --test secret_leak_gate`).
# `--expect-tests` (R6-W-7, 2026-08-14) adds a NAME-level assertion on top of
# the count: every listed test name must appear in the run output as a
# passed test (`test <name> ... ok`). This closes the count-only hole where
# a suite is hollowed out but the floor is still met — the count pin is a
# lower bound, so deleting a non-gate test file while keeping >= min passing
# tests passes it; a name that is deleted, #[ignore]d, or cfg-emptied fails
# regardless of the remaining count. A unit-test name inside a module is
# matched by its bare fn name (`foo` matches `module::tests::foo`); when a
# name is not unique across the workspace's modules, the pin MUST use the
# fully qualified name (`module::tests::foo`) — the match is a suffix
# match, so the qualified form is matched exactly and cannot collide. Each
# expected name is Rust-identifier-shaped: a non-empty `[A-Za-z_]
# [A-Za-z0-9_]*` per `::` segment (W7-M-1). The ci.yml pin lists keep the
# bare form today — the 21 registered names are unique workspace-wide
# (verified in the wave-seven A4 register); switch any of them to the
# qualified form only if a same-named test appears in a second module.
#
# The count is the sum of the `test result: ok. N passed; ...` lines libtest
# prints per test binary (one per binary; doc-test harnesses included). A
# cargo error (missing test target, compile error, failing test) is
# propagated as the step's failure; a run with zero passing tests — no
# `test result: ok.` line at all, or a sum below the pin — fails the
# assertion.
#
# Exit codes: 0 = >= min-passed tests passed and every expected name ran;
# 1 = fewer passed (or no `test result` line seen) or an expected name is
# missing; otherwise cargo's own exit code.
set -uo pipefail
# (no `-e` by design: cargo's exit status is captured below so its output
# can be echoed to the log before the step fails — an `-e` abort would
# swallow the test output that the failure diagnosis needs)

die() { echo "assert-tests-ran.sh: ERROR: $*" >&2; exit 1; }

[ "$#" -ge 2 ] || die "usage: scripts/assert-tests-ran.sh <min-passed> [--expect-tests name1,name2,...] [cargo test args...]"
min="$1"
shift
case "$min" in
    0 | [1-9] | [1-9][0-9]*) ;;
    *) die "min-passed must be a non-negative integer without a leading zero (bash arithmetic parses leading zeros as octal), got: $min" ;;
esac

# Split off --expect-tests <list>; everything else is a cargo test argument.
expect=""
args=()
while [ "$#" -gt 0 ]; do
    case "$1" in
        --expect-tests)
            [ "$#" -ge 2 ] || die "--expect-tests requires a comma-separated test-name list"
            expect="$2"
            shift 2
            ;;
        *)
            args+=("$1")
            shift
            ;;
    esac
done
set -- "${args[@]}"

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

# Name-level assertion (R6-W-7): every expected name must appear in a
# `test <name> ... ok` line. #[ignore]d tests print `... ignored` and do not
# count as having run.
if [ -n "$expect" ]; then
    ran="$(printf '%s\n' "$out" | sed -n 's/^test \([^ ]*\) \.\.\. ok$/\1/p')"
    missing=""
    IFS=',' read -ra names <<< "$expect"
    for name in "${names[@]}"; do
        # W7-M-1: a name may be fully qualified (`module::tests::foo`) to
        # disambiguate same-named tests across modules. Every `::` segment
        # must be a Rust identifier — a non-empty [A-Za-z_][A-Za-z0-9_]*
        # — so `a::1b`, empty segments, and stray characters are refused.
        # (The segments are peeled off one at a time instead of IFS-split,
        # because IFS treats every ':' as a delimiter, which would split
        # `a::b` into an empty middle segment.)
        remaining="$name"
        while :; do
            case "$remaining" in
                *::*)
                    head="${remaining%%::*}"
                    remaining="${remaining#*::}"
                    case "$head" in
                        '' | [!A-Za-z_]* | *[!A-Za-z0-9_]*)
                            die "invalid expected test name '$name' — every '::' segment must be a Rust identifier [A-Za-z_][A-Za-z0-9_]*" ;;
                    esac
                    ;;
                *)
                    case "$remaining" in
                        '' | [!A-Za-z_]* | *[!A-Za-z0-9_]*)
                            die "invalid expected test name '$name' — every '::' segment must be a Rust identifier [A-Za-z_][A-Za-z0-9_]*" ;;
                    esac
                    break
                    ;;
            esac
        done
        # Here-strings, not pipelines: under `set -o pipefail` a
        # `printf | grep -q` whose grep exits early (first match) sends
        # SIGPIPE to a still-writing printf, pipefail turns the pipeline
        # into a failure, and `!` flips a successful match into a false
        # "did not run". The workspace run hit this on ubuntu on the first
        # real execution (run 31795473166): names matching early in the
        # ~60 KB ran list failed, names matching late passed — position
        # dependent, never deterministic. A here-string's exit status is
        # grep's alone.
        if ! grep -qx "$name" <<<"$ran" && ! grep -qxE ".*::$name" <<<"$ran"; then
            missing="$missing $name"
        fi
    done
    if [ -n "$missing" ]; then
        die "expected tests did not run (deleted, #[ignore]d, or cfg-emptied?):$missing"
    fi
fi

echo "assert-tests-ran.sh: $passed tests passed (pinned minimum: $min${expect:+, expected names all ran})"
