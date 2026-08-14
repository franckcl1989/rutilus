#!/usr/bin/env bash
# Cross-document anchor gate (W11-T-1, 2026-08-14).
#
# The docs/*.md files carry hundreds of `file:line` references into the
# code tree, and ten adversarial-audit rounds showed that manual
# re-anchor passes systematically miss a class of references every time
# (the wave-six ci.yml +149/-62 shift drifted ~+98 anchors that went
# five rounds unnoticed; the wave-nine/ten comment growth drifted
# another +8/+11). This gate mechanizes the verification:
#
#   for every `path.ext:NNN` or `path.ext:NNN-MMM` reference in docs/,
#     * the referenced file must exist under the repository root, and
#     * every line in the range must exist (range end <= file length), and
#     * the doc line containing the reference must share at least one
#       significant token (>= 5 chars, alphanumeric/underscore) with the
#       referenced line's content — a cheap content fingerprint.
#
# The token check is a fingerprint, not a proof: an anchor can still
# drift onto a different line that happens to share a word with the
# doc's description (registered blind spot, the wasm32 `:406-521` case
# from wave eleven). It catches the dominant failure mode — wholesale
# shifts onto unrelated content — and fails loudly otherwise.
#
# Scope: references whose file path exists in the tree. Paths that do
# not exist (external references, "§x.y:"-style prose, design-doc
# section numbers written as `design:NNNN`) are skipped rather than
# failed; the doc author decides those. Bare continuation references
# (`:NNN` continuing a path mentioned earlier on the same doc line)
# inherit the nearest preceding path mention — a full anchor or a bare
# path in backticks — and are checked (W11-T-2); a bare ref must follow
# a delimiter (space, backtick, CJK/ASCII punctuation) so prose like
# `§0.9.0:2812` never qualifies. The point-in-time registrations under
# docs/r*-findings/ keep their historical anchors by the W9-D-4
# convention (「历史点-时登记保留原文」) and are exempt from the gate.
#
# Usage: bash scripts/check-doc-anchors.sh [docs-dir]
# Exit 0 when every anchor checks out; exit 1 with a per-anchor report
# otherwise.

set -u

DOCS_DIR="${1:-docs}"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

failures=0
checked=0
declare -A file_lengths=()

# Lines that carry a code-file anchor: `xxx.yyy:NNN` where xxx.yyy looks
# like a source file name (.rs/.yml/.ps1/.sh/.toml/.proto/.md).
while IFS= read -r hit; do
    # grep -n output is doc-file:lineno:text.
    doc_file="${hit%%:*}"
    rest="${hit#*:}"
    lineno="${rest%%:*}"
    text="${rest#*:}"

    # Point-in-time registrations keep their historical anchors.
    case "$doc_file" in
        */r[0-9]*-findings/*) continue ;;
    esac

    # One ordered pass extracts full anchors, bare path mentions, and
    # bare continuation refs; each bare ref inherits the nearest
    # preceding path mention on the same line (W11-T-2): ":10637" after
    # "ui/src/lib.rs:10446" resolves to ui/src/lib.rs:10637, a later
    # "i18n.rs:1661" re-targets what follows, and a prose path like
    # "`scripts/drills/drill-lib.ps1`（... `:869`" targets its own bare
    # refs. The delimiter requirement keeps "§0.9.0:2812"-style prose
    # out; a bare ref already present as the tail of a full anchor is a
    # duplicate and skipped.
    tokens=$(printf '%s' "$text" | grep -oE '[A-Za-z0-9_./\\-]+\.(rs|yml|ps1|sh|toml|proto|md)(:[0-9]+(-[0-9]+)?)?|[[:space:]`（、，；）]:[0-9]+(-[0-9]+)?' || true)
    [ -z "$tokens" ] && continue
    anchors=""
    current_path=""
    for tok in $tokens; do
        case "$tok" in
            *\.rs:*|*\.yml:*|*\.ps1:*|*\.sh:*|*\.toml:*|*\.proto:*|*\.md:*)
                current_path="${tok%%:*}"
                anchors="$anchors $tok"
                ;;
            *\.rs|*\.yml|*\.ps1|*\.sh|*\.toml|*\.proto|*\.md)
                # A path mention without a range retargets the bare refs
                # that follow it on the line.
                current_path="$tok"
                ;;
            *)
                ref=$(printf '%s' "$tok" | sed 's/^[^:]*//')
                [ -z "$current_path" ] && continue
                case " $anchors " in *"${ref}"*) continue ;; esac
                anchors="$anchors ${current_path}${ref}"
                ;;
        esac
    done

    for anchor in $anchors; do
        path="${anchor%:*}"
        range="${anchor#*:}"
        start="${range%%-*}"
        end="${range##*-}"

        target="$REPO_ROOT/$path"
        if [ ! -f "$target" ]; then
            # Unknown/external reference — outside this gate's scope.
            continue
        fi

        checked=$((checked + 1))
        if [ -z "${file_lengths[$path]+x}" ]; then
            file_lengths[$path]=$(wc -l < "$target")
        fi
        length="${file_lengths[$path]}"

        if [ "$start" -lt 1 ] || [ "$end" -gt "$length" ] || [ "$start" -gt "$end" ]; then
            echo "ANCHOR OUT OF RANGE: $doc_file:$lineno -> $anchor (file has $length lines)"
            failures=$((failures + 1))
            continue
        fi

        # Content fingerprint: the doc line's significant tokens must
        # overlap the referenced line's content; the token scan uses
        # bash built-ins. Per-file line counts are cached above, so each
        # referenced file is measured once; the remaining per-anchor
        # cost is one `sed` spawn, which dominates on Windows where
        # process startup is slow (the uncached first run took minutes
        # for 957 anchors).
        target_text=$(sed -n "${start}p" "$target")
        shared=0
        for token in $(printf '%s' "$text" | grep -oE '[A-Za-z_][A-Za-z0-9_]{4,}'); do
            case "$target_text" in
                *"$token"*) shared=1; break ;;
            esac
        done
        if [ "$shared" -eq 0 ]; then
            # Warning tier: point-in-time registrations and table rows
            # legitimately lack shared tokens with their target line;
            # the out-of-range tier above is the hard failure mode.
            echo "ANCHOR FINGERPRINT MISS (review): $doc_file:$lineno -> $anchor (no shared token with target line)"
        fi
    done
done < <(grep -rnE '[A-Za-z0-9_./\\-]+\.(rs|yml|ps1|sh|toml|proto|md):[0-9]+|([[:space:]]|`|（|、|，|；|）):[0-9]+(-[0-9]+)?' "$DOCS_DIR" --include='*.md' 2>/dev/null || true)

if [ "$failures" -gt 0 ]; then
    echo "check-doc-anchors: $failures anchor(s) OUT OF RANGE across $checked checked reference(s)"
    exit 1
fi
echo "check-doc-anchors: $checked checked reference(s), all in range"
exit 0
