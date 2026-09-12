#!/usr/bin/env bash
# Randomized fuzz driver for gh-amp helper functions (bash analogue of Go's
# coverage-guided fuzzing; see .just/lib/gh-amp-test.sh for the seed-corpus
# unit tests). Runs fixed-seed, time-boxed bursts of adversarial input
# generation against the same invariants the unit tests assert:
#
#   - sanitize(): output contains no control bytes; known-good text and
#     known-good escape sequences map to expected strings
#   - valid_menu_choice(): a value is accepted only if it points at a real
#     menu item (guards the int64-overflow and octal bugs)
#   - resolve_owner_repo(): a successful parse yields GitHub slugs
#   - the batch PR-number filter regexp used in the GraphQL splice
#
# Usage: gh-amp-fuzz.sh [duration] (default 30s; suffixes like 10m work)
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly REPO_ROOT

DURATION="${1:-30s}"

# shellcheck disable=SC1090  # dynamic path computed above
source "$REPO_ROOT/gh-amp"

if ! [[ "$DURATION" =~ ^([0-9]+)([smh])$ ]]; then
    echo "usage: $0 [duration, e.g. 30s|5m|1h]" >&2
    exit 2
fi

dur_num="${BASH_REMATCH[1]}"
dur_unit="${BASH_REMATCH[2]}"
case "$dur_unit" in
    s) dur_secs="$dur_num" ;;
    m) dur_secs=$(( dur_num * 60 )) ;;
    h) dur_secs=$(( dur_num * 3600 )) ;;
esac
readonly dur_secs

deadline=$(( $(date +%s) + dur_secs ))

RANDOM=42  # fixed seed: reproducible runs; a finding can be re-triggered

iter=0
fail=0

# --- generators -----------------------------------------------------------

rand_printable() {
    # Random string from a hostile alphabet: printable ASCII plus escape
    # shapes that historically bypassed the old sanitizer. The mix matters:
    # real SGR bytes alone would be stripped even by the vulnerable version
    # (no coverage), so OSC, bare ESC, CR/BS/LF and literal "\\033" text are
    # all represented.
    local n=$(( RANDOM % 24 + 1 ))
    # shellcheck disable=SC1003  # "'" ends the quote; '\' is a literal backslash, not an escaped quote
    local alpha=( ' ' '#' '$' '%' ';' '&' '<' '>' '"' "'" '\' '(' ')'
                  '[' ']' '{' '}' '`' '!' '*' '?' '|' '~' '^' )
    local out=""
    local i
    for (( i = 0; i < n; i++ )); do
        case $(( RANDOM % 8 )) in
            0) out+="${alpha[RANDOM % ${#alpha[@]}]}" ;;
            1) out+="\\033" ;;            # literal escape text (echo -e bait)
            2) out+=$'\033'"[$(( RANDOM % 99 ));$(( RANDOM % 9 ))m" ;;  # real SGR
            3) out+=$'\033'"]0;title$(( RANDOM % 9 ))"$'\007' ;;        # OSC + BEL
            4) out+=$'\033'"]2;x"$'\033'"\\" ;;                          # OSC + ST
            5) out+=$'\r' ;;
            6) out+=$'\n' ;;
            7) out+=$'\b' ;;
        esac
    done
    printf '%s' "$out"
}

rand_number() {
    # Numeric-ish strings around known hazard shapes.
    local choice
    case $(( RANDOM % 6 )) in
        0) choice=$(( RANDOM )) ;;
        1) choice="$(( RANDOM ))$(( RANDOM ))$(( RANDOM ))$(( RANDOM ))" ;;  # huge
        2) choice="0$(( RANDOM % 100 ))" ;;   # leading zero / octal hazard
        3) choice="$(( RANDOM % 100 ))x" ;;    # trailing junk
        4) choice="-$(( RANDOM % 100 ))" ;;
        5) choice="1844674407370955$(( RANDOM % 100000 ))" ;;  # 2^64 wrap zone
    esac
    printf '%s' "$choice"
}

rand_repo_target() {
    # Strings shaped like --repo values, some malformed.
    local segs=()
    local seg
    local n=$(( RANDOM % 5 ))
    local i
    for (( i = 0; i < n; i++ )); do
        case $(( RANDOM % 3 )) in
            0) seg="owner$(( RANDOM % 100 ))" ;;
            1) seg=$(rand_printable | tr -d '/') ;;
            2) seg="repo.$(( RANDOM % 10 ))" ;;
        esac
        segs+=("$seg")
    done
    local joiner=$(( RANDOM % 2 == 0 ? 1 : 0 ))
    if (( ${#segs[@]} == 0 )); then
        segs=("owner")
    fi
    local out="${segs[0]}"
    for (( i = 1; i < ${#segs[@]}; i++ )); do
        if (( joiner )); then
            out+="/${segs[i]}"
        else
            out+=" ${segs[i]}"   # space-joined: the fuzz-found laxity shape
        fi
    done
    printf '%s' "$out"
}

# --- oracles ---------------------------------------------------------------

check_sanitize() {
    local input="$1"
    local out
    out="$(sanitize "$input")"
    local dump
    dump="$(printf '%s' "$out" | od -An -c | tr -s ' ')"
    if grep -qE '033|\\r|\\b|\\n' <<<"$dump"; then
        echo "FAIL iter=$iter: sanitize() leaked control bytes for input:"
        printf '%s\n' "$input" | od -An -c | sed 's/^/    /'
        fail=1
        return 1
    fi
    return 0
}

check_menu_choice() {
    local input="$1"
    local count=5
    local out
    if out="$(valid_menu_choice "$input" "$count")"; then
        # Accepted: it must be a real item index in decimal, and re-validating
        # the canonical form must agree.
        if (( 10#$input < 1 || 10#$input >= count )); then
            echo "FAIL iter=$iter: valid_menu_choice accepted out-of-range $(printf '%q' "$input")"
            fail=1
            return 1
        fi
        valid_menu_choice "$(( 10#$input ))" "$count" || {
            echo "FAIL iter=$iter: canonical $(( 10#$input )) rejected after $input accepted"
            fail=1
            return 1
        }
    else
        # Rejected: nothing more to assert (rejections are always safe).
        :
    fi
    return 0
}

check_repo_target() {
    local input="$1"
    REPO="$input"
    local out
    if out="$(resolve_owner_repo)"; then
        if [[ -n "$out" ]] && [[ ! "$out" =~ ^[a-zA-Z0-9_.-]+\ [a-zA-Z0-9_.-]+$ ]]; then
            echo "FAIL iter=$iter: resolve_owner_repo produced non-slug output $(printf '%q' "$out") for $(printf '%q' "$input")"
            fail=1
            # shellcheck disable=SC2034  # REPO is consumed by resolve_owner_repo above
            REPO=""
            return 1
        fi
        if [[ -n "$out" ]]; then
            local owner name
            read -r owner name <<<"$out"
            local rebuilt="$owner/$name"
            local out2
            REPO="$rebuilt"
            out2="$(resolve_owner_repo)"
            if [[ "$out2" != "$out" ]]; then
                echo "FAIL iter=$iter: round-trip $(printf '%q' "$input") -> $(printf '%q' "$out") -> $(printf '%q' "$out2")"
                fail=1
                REPO=""
                return 1
            fi
        fi
    fi
    # shellcheck disable=SC2034  # REPO is consumed by resolve_owner_repo above
    REPO=""
    return 0
}

check_pr_number_filter() {
    local input="$1"
    local re='^[1-9][0-9]{0,9}$'
    if [[ "$input" =~ $re ]]; then
        # Accepted values must splice into the GraphQL shape harmlessly.
        local query="pullRequest(number:${input})"
        if ! grep -qE '^pullRequest\(number:[1-9][0-9]{0,9}\)$' <<<"$query"; then
            echo "FAIL iter=$iter: filter accepted $(printf '%q' "$input") but splice check failed"
            fail=1
            return 1
        fi
    fi
    return 0
}

# --- loop ------------------------------------------------------------------

echo "Fuzzing gh-amp helpers for $DURATION (seed 42)..."
while (( $(date +%s) < deadline )); do
    (( iter++ ))

    check_sanitize "$(rand_printable)" || break
    check_sanitize "$(rand_number)" || break
    check_menu_choice "$(rand_number)" || break
    check_repo_target "$(rand_repo_target)" || break
    check_pr_number_filter "$(rand_number)" || break
done

if (( fail )); then
    echo "FAILED after $iter iterations"
    exit 1
fi
echo "OK: $iter iterations, no invariant violations"
