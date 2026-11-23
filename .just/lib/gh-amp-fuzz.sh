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
#   - classify_check_buckets(): bucket JSON on stdin prints exactly one
#     of failing|pending|passing, or nothing at all for no-signal shapes
#     (empty input, empty array, non-array or malformed JSON); fail/cancel
#     beats pending beats pass regardless of element order or repetition
#
# Usage: gh-amp-fuzz.sh [duration] (default 30s; suffixes like 10m work)
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly REPO_ROOT

DURATION="${1:-30s}"

# Validate arguments before sourcing anything else: fail fast on usage
# errors rather than doing setup work first (third review pass of #41).
if ! [[ "$DURATION" =~ ^([0-9]+)([smh])$ ]]; then
    echo "usage: $0 [duration, e.g. 30s|5m|1h]" >&2
    exit 2
fi

# shellcheck disable=SC1090  # dynamic path computed above
source "$REPO_ROOT/gh-amp"

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

rand_bucket_json() {
    # Emit "<expected> <json>" for classify_check_buckets, where expected
    # is failing|pending|passing|none ("none" = expect empty output, the
    # caller's degradation cue). Two shape classes:
    #
    #   well-formed: an array of 0..8 elements, every element an OBJECT.
    #     Each element draws a semantic first (fail/pending/pass/neutral),
    #     then a concrete spelling: real buckets, JSON-escaped spellings,
    #     case-mangled and padded lookalikes, output words as input,
    #     non-string values, missing keys. Order and repetition are free,
    #     so mixed draws exercise precedence every time.
    #   no-signal: empty input, [], non-array JSON, malformed JSON, and
    #     all-non-object arrays -- expected "none". A stray "passing" for
    #     any of these would be the misleading green light issue #21
    #     guards against.
    #
    # jq-version determinism (the issue #55 caveat): generated arrays NEVER
    # mix object elements with non-object elements. Shapes like
    # [{"bucket":"fail"},1] are jq-version-dependent -- modern jq
    # short-circuits any/2 to "failing" while jq 1.6-era builds error and
    # print nothing -- so they are excluded here exactly as
    # test_classify_check_buckets excludes them. [1,2] is safe (its
    # non-object element errors on every jq before any short-circuit
    # question can matter) and stays.
    local shape=$(( RANDOM % 5 ))
    if (( shape == 0 )); then
        local junk
        case $(( RANDOM % 9 )) in
            0) junk='' ;;
            1) junk='[]' ;;
            2) junk='null' ;;
            3) junk='not json' ;;
            4) junk='{}' ;;
            5) junk='42' ;;
            6) junk='[1,2]' ;;
            7) junk='[{"bucket":"fail"' ;;                # truncated
            8) junk='"[{\"bucket\":\"fail\"}]"' ;;        # double-encoded
        esac
        printf 'none %s' "$junk"
        return
    fi

    local n=$(( RANDOM % 9 ))
    local json='['
    local has_fail=0 has_pending=0
    local i spelling
    for (( i = 0; i < n; i++ )); do
        (( i > 0 )) && json+=','
        case $(( RANDOM % 4 )) in
            0)  # fail semantic: must classify failing wherever it appears
                has_fail=1
                case $(( RANDOM % 3 )) in
                    0) spelling='{"bucket":"fail"}' ;;
                    1) spelling='{"bucket":"cancel"}' ;;
                    2) spelling='{"bucket":"\u0066ail"}' ;;  # escaped "fail"
                esac
                ;;
            1)  # pending semantic: outranks pass, loses to fail
                has_pending=1
                spelling='{"bucket":"pending"}'
                ;;
            2)  # pass semantic
                case $(( RANDOM % 2 )) in
                    0) spelling='{"bucket":"pass"}' ;;
                    1) spelling='{"bucket":"skipping"}' ;;
                esac
                ;;
            3)  # neutral: must never match any bucket test
                case $(( RANDOM % 9 )) in
                    0) spelling='{}' ;;                         # missing key
                    1) spelling='{"bucket":null}' ;;
                    2) spelling='{"bucket":1}' ;;
                    3) spelling='{"bucket":["fail"]}' ;;        # array value
                    4) spelling='{"bucket":"FAIL"}' ;;          # wrong case
                    5) spelling='{"bucket":"fail "}' ;;         # padded
                    6) spelling='{"bucket":"passing"}' ;;       # output word as input
                    7) spelling='{"bucket":"failing"}' ;;
                    8) spelling='{"bucket":"\\033[31mfail"}' ;; # literal escape text
                esac
                ;;
        esac
        json+="$spelling"
    done
    json+=']'

    local expected
    if (( has_fail )); then
        expected=failing
    elif (( has_pending )); then
        expected=pending
    elif (( n > 0 )); then
        expected=passing
    else
        expected=none   # the "[]" draw
    fi
    printf '%s %s' "$expected" "$json"
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

check_classify_buckets() {
    # Exact-match oracle for classify_check_buckets. $1 is the expected
    # token from rand_bucket_json (failing|pending|passing|none), $2 the
    # JSON to classify. "none" means no-signal: the function must print
    # NOTHING -- empty output is the caller's degradation cue, and a stray
    # "passing" would be the misleading green light issue #21 guards
    # against. Exact match also enforces the never-partial invariant:
    # "fail" or "failing\njunk" both miss.
    local expected="$1" input="$2"
    local want=""
    [[ "$expected" != none ]] && want="$expected"
    local out
    out="$(printf '%s' "$input" | classify_check_buckets)"
    if [[ "$out" != "$want" ]]; then
        echo "FAIL iter=$iter: classify_check_buckets: expected $(printf '%q' "$want") but got $(printf '%q' "$out") for input:"
        printf '%s\n' "$input" | od -An -c | sed 's/^/    /'
        fail=1
        return 1
    fi
    return 0
}

check_classify_soup() {
    # Universal invariant for arbitrary garbage: whatever bytes go in, the
    # output is exactly one of failing|pending|passing or empty -- never a
    # partial word, never extra text. Demanding empty here is not sound:
    # the soup generators can legitimately assemble `[{}]` (legal JSON,
    # non-empty object array, no bucket keys), which correctly classifies
    # as "passing" -- the else branch treats unknown or missing buckets
    # as green unless fail/cancel/pending appears. The bucket-aware
    # generator pins exact outputs; this pins the output vocabulary for
    # shapes nobody predicted.
    local input="$1"
    local out
    out="$(printf '%s' "$input" | classify_check_buckets)"
    if [[ ! "$out" =~ ^(failing|pending|passing)?$ ]]; then
        echo "FAIL iter=$iter: classify_check_buckets emitted $(printf '%q' "$out") for garbage input:"
        printf '%s\n' "$input" | od -An -c | sed 's/^/    /'
        fail=1
        return 1
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
    gen="$(rand_bucket_json)"
    check_classify_buckets "${gen%% *}" "${gen#* }" || break
    check_classify_soup "$(rand_printable)" || break
    check_classify_soup "$(rand_number)" || break
done

if (( fail )); then
    echo "FAILED after $iter iterations"
    exit 1
fi
echo "OK: $iter iterations, no invariant violations"
