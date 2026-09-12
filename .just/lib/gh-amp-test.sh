#!/usr/bin/env bash
# Test suite for gh-amp helper functions (the bash analogue of gh-observer's
# Go fuzz targets, PR fini-net/gh-observer#450).
#
# Sources the gh-amp script (whose main() is guarded to run only when
# executed, not sourced) and exercises the functions that parse or render
# untrusted input:
#
#   - sanitize()               -- escape/control-byte stripping
#   - valid_menu_choice()      -- interactive menu selection validation
#   - resolve_owner_repo()     -- OWNER/REPO slug parsing for GraphQL
#   - lookup_check_status()    -- checks-map key lookup
#   - color_for_status()       -- status -> color mapping
#   - the batch PR-number filter (via the regexp it uses)
#
# Each section runs a seed corpus of known-good, known-bad, and adversarial
# inputs (the same shapes that found the fixed bugs: OSC injection, literal
# "\033" text re-interpreted by echo -e, 64-bit integer wrap in menu
# choices, and non-slug path segments spliced into GraphQL). Deeper
# randomized exploration is opt-in via `just fuzz`.
set -euo pipefail

readonly T_RED='\033[0;31m'
readonly T_GREEN='\033[0;32m'
readonly T_BLUE='\033[0;34m'
readonly T_NORMAL='\033[0m'

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly REPO_ROOT
readonly AMP="$REPO_ROOT/gh-amp"

passed=0
failed=0

# shellcheck disable=SC1090  # dynamic path computed above
source "$AMP"

assert_eq() {
    local label="$1" expected="$2" actual="$3"
    if [[ "$expected" != "$actual" ]]; then
        echo "    ${T_RED}assertion failed:${T_NORMAL} $label"
        echo "      expected: $(printf '%q' "$expected")"
        echo "      actual:   $(printf '%q' "$actual")"
        return 1
    fi
    return 0
}

assert_match() {
    local label="$1" pattern="$2" actual="$3"
    if ! printf '%s' "$actual" | grep -qE "$pattern"; then
        echo "    ${T_RED}assertion failed:${T_NORMAL} $label"
        echo "      expected match: /$pattern/"
        echo "      actual:   $(printf '%q' "$actual")"
        return 1
    fi
    return 0
}

# assert_no_control_bytes fails when $1 contains any control byte: the C0
# range (0x00-0x1f) plus DEL (0x7f). od -c output pattern-matches specific
# escape spellings and silently passes others (e.g. BEL, \f, \v), so this
# inspects the decimal byte dump instead. od pads short rows with leading
# spaces, so squeeze whitespace before awk: empty fields would otherwise
# coerce to 0 in the numeric comparison and defeat the check. Literal
# backslash text (bytes 5c 6e for "\n") is unaffected -- that is inert
# display text, exactly what sanitize() is supposed to leave behind.
assert_no_control_bytes() {
    local label="$1" s="$2"
    local bad
    bad="$(printf '%s' "$s" | od -An -tu1 | tr -s ' \t' '\n' | awk 'NF && ($1 < 32 || $1 == 127) {print $1; exit}')"
    if [[ -n "$bad" ]]; then
        echo "    ${T_RED}assertion failed:${T_NORMAL} $label: control byte(s) survive (first: $bad):"
        printf '%s' "$s" | od -An -c | sed 's/^/      /'
        return 1
    fi
    return 0
}

record() {
    local label="$1" ok="$2"
    if [[ "$ok" == true ]]; then
        echo -e "  ${T_GREEN}✓${T_NORMAL} $label"
        (( passed += 1 ))
    else
        echo -e "  ${T_RED}✗${T_NORMAL} $label"
        (( failed += 1 ))
    fi
    return 0
}

test_sanitize() {
    local ok=true

    # Known-good: ordinary text passes through untouched.
    assert_eq "sanitize plain" "Add fuzzy matching to gh amp" \
        "$(sanitize "Add fuzzy matching to gh amp")" || ok=false
    assert_eq "sanitize unicode" "héllo wörld → ✓" \
        "$(sanitize "héllo wörld → ✓")" || ok=false

    # SGR color codes are stripped (pre-existing behavior).
    assert_eq "sanitize sgr" "aredb" \
        "$(sanitize $'a\033[31mred\033[0mb')" || ok=false

    # Adversarial seeds: OSC title injection (found by fuzzing).
    assert_eq "sanitize osc-bel" "after" \
        "$(sanitize $'\033]0;pwned\007after')" || ok=false
    assert_eq "sanitize osc-st" "after" \
        "$(sanitize $'\033]0;x\033\\after')" || ok=false
    assert_eq "sanitize osc-only" "" \
        "$(sanitize $'\033]0;title\007')" || ok=false

    # Other CSI codes (cursor movement, erase) are stripped too -- including
    # private/intermediate-parameter forms like ESC[?25h and ESC[!p, which a
    # digits-only parameter class used to leave behind as inert "[?25h" text
    # (third review pass of #41).
    assert_eq "sanitize csi-erase" "cursor" \
        "$(sanitize $'\033[2J\033[1;5Hcursor')" || ok=false
    assert_eq "sanitize csi-private" "cursor-on" \
        "$(sanitize $'\033[?25hcursor-on')" || ok=false
    assert_eq "sanitize csi-intermediate" "reset" \
        "$(sanitize $'\033[!preset')" || ok=false

    # CR/BS rewrite attacks and interior LF (menu-line forgery).
    assert_eq "sanitize cr-bs" "xyz" \
        "$(sanitize $'x\ry\bz')" || ok=false
    assert_eq "sanitize lf" "ab" \
        "$(sanitize $'a\nb')" || ok=false

    # Stray ESC and BEL must not survive.
    assert_eq "sanitize bare-esc" "" "$(sanitize $'\033')" || ok=false
    assert_eq "sanitize bel" "bell" "$(sanitize $'\007bell')" || ok=false

    record "sanitize()" "$ok"
}

test_valid_menu_choice() {
    local ok=true

    # Valid selections.
    if ! valid_menu_choice 1 5; then
        echo "    1 of 5 rejected"; ok=false
    fi
    if ! valid_menu_choice 4 5; then
        echo "    4 of 5 rejected"; ok=false
    fi

    # Boundary rejections: 0 and count itself are not items.
    valid_menu_choice 0 5 && { echo "    0 accepted"; ok=false; }
    valid_menu_choice 5 5 && { echo "    count accepted"; ok=false; }

    # Non-numeric and empty.
    valid_menu_choice abc 5 && { echo "    abc accepted"; ok=false; }
    valid_menu_choice "" 5 && { echo "    empty accepted"; ok=false; }
    valid_menu_choice "1x" 5 && { echo "    1x accepted"; ok=false; }
    valid_menu_choice " 1" 5 && { echo "    space-padded accepted"; ok=false; }

    # Integer-overflow wrap (found by fuzzing): 2^64+3 wraps to 3 under
    # int64 arithmetic and used to select item 3. The length cap rejects it.
    valid_menu_choice 18446744073709551619 5 && { echo "    2^64+3 accepted"; ok=false; }
    valid_menu_choice 99999999999999999999 5 && { echo "    20-digit accepted"; ok=false; }

    # Leading zeros are octal hazards ("08" is a parse error, not 8).
    valid_menu_choice 08 5 && { echo "    08 accepted"; ok=false; }
    valid_menu_choice 007 5 && { echo "    007 accepted"; ok=false; }

    record "valid_menu_choice()" "$ok"
}

test_resolve_owner_repo() {
    local ok=true
    local out

    # Valid: plain owner/repo slugs.
    REPO="fini-net/gh-amp"
    out="$(resolve_owner_repo)"
    assert_eq "plain slug" "fini-net gh-amp" "$out" || ok=false

    # Valid: host-prefixed form (one leading segment is stripped).
    REPO="github.com/fini-net/gh-amp"
    out="$(resolve_owner_repo)"
    assert_eq "host-prefixed" "fini-net gh-amp" "$out" || ok=false

    # Valid: dots and underscores are legal slug characters.
    REPO="o.name/re_name-2"
    out="$(resolve_owner_repo)"
    assert_eq "dotted slug" "o.name re_name-2" "$out" || ok=false

    # Adversarial: extra path segments used to yield owner="b", name="c/d".
    REPO="a/b/c/d"
    out="$(resolve_owner_repo)"
    [[ -z "$out" ]] || { echo "    a/b/c/d accepted: $out"; ok=false; }

    # Adversarial: spaces must not parse as slugs (found by fuzzing).
    REPO="host/o wner/re po"
    out="$(resolve_owner_repo)"
    [[ -z "$out" ]] || { echo "    spaced repo accepted: $out"; ok=false; }

    # Degenerate shapes. (Empty REPO is not listed: when REPO is empty the
    # function intentionally falls back to the current repo via gh, which is
    # exercised by the live test_list/test_review recipes instead.)
    for r in "x//y" "_" "owner/" "/repo" "a/b/" "owner" "o wner/re po"; do
        REPO="$r"
        out="$(resolve_owner_repo)"
        [[ -z "$out" ]] || { echo "    [$r] accepted: $out"; ok=false; }
    done
    # shellcheck disable=SC2034  # reset for later tests
    REPO=""

    record "resolve_owner_repo()" "$ok"
}

test_lookup_check_status() {
    local ok=true
    local map="42 passing
7 failing
13 pending"

    assert_eq "found" "passing" "$(lookup_check_status 42 "$map")" || ok=false
    assert_eq "found failing" "failing" "$(lookup_check_status 7 "$map")" || ok=false
    assert_eq "missing" "" "$(lookup_check_status 99 "$map")" || ok=false
    assert_eq "empty status line" "" "$(lookup_check_status 8 "$map")" || ok=false

    # Non-numeric keys are rejected, not passed to awk.
    assert_eq "non-numeric key" "" "$(lookup_check_status "1 2" "$map")" || ok=false
    assert_eq "backslash key" "" "$(lookup_check_status '4\2' "$map")" || ok=false

    record "lookup_check_status()" "$ok"
}

test_batch_pr_number_filter() {
    # The filter regex used by batch_checks_status before splicing numbers
    # into a GraphQL query string. Kept in sync with the script; the fuzz
    # suite exercises it through generated numbers.
    local ok=true
    local re='^[1-9][0-9]{0,9}$'

    for n in 1 7 42 12345 999999999 1234567890; do
        [[ "$n" =~ $re ]] || { echo "    $n rejected"; ok=false; }
    done
    for n in 0 007 08 18446744073709551619 99999999999999999999 "42x" "x42" "4 2" "4.2" "-42" "" "4\\2"; do
        [[ "$n" =~ $re ]] && { echo "    $n accepted"; ok=false; }
    done

    record "batch PR-number filter" "$ok"
}

test_color_for_status() {
    local ok=true

    assert_match "passing->green" $'\033\[32m' "$(color_for_status passing)" || ok=false
    assert_match "pending->yellow" $'\033\[33m' "$(color_for_status pending)" || ok=false
    assert_match "failing->red" $'\033\[31m' "$(color_for_status failing)" || ok=false
    assert_match "unknown->reset" $'\033\[0m' "$(color_for_status bogus)" || ok=false

    record "color_for_status()" "$ok"
}

test_display_inert() {
    # The display fix: untrusted titles must render as inert text. Reproduce
    # the select_pr/review_pr printf pattern and assert no escape bytes are
    # emitted and no extra lines are forged.
    local ok=true
    local title='\033[31mEVIL\n99) Exit'

    local sanitized out
    sanitized="$(sanitize "$title")"
    out="$(printf '%s' "  1)  #7  "; printf '%s\n' "$sanitized")"

    # Literal backslash text survives (the user sees the raw characters)...
    assert_match "literal text preserved" '\\033\[31mEVIL' "$out" || ok=false
    # ...but emits no real escape bytes and forges no second line.
    assert_no_control_bytes "no escape bytes in rendered title" "$out" || ok=false
    [[ "$(printf '%s\n' "$out" | wc -l)" -eq 1 ]] || {
        echo "    rendered title spans multiple lines"; ok=false
    }

    record "display renders untrusted titles inertly" "$ok"
}

test_log_streams() {
    # Stream contract for the log helpers (second review pass of #41): each
    # helper must write its icon AND message to one stream. A split (icon on
    # stdout, message on stderr) leaks a bare colored icon into consumers
    # capturing only stdout and loses the icon for stderr-only consumers.
    # log_info/log_success: stdout. log_warn/log_error: stderr (matches the
    # Unix convention and the original log_error behavior).
    local ok=true
    local out err

    out="$(log_info "info message" 2>/dev/null)"
    assert_match "log_info icon on stdout" 'ℹ' "$out" || ok=false
    assert_match "log_info message on stdout" 'info message' "$out" || ok=false
    out="$(log_success "success message" 2>/dev/null)"
    assert_match "log_success icon on stdout" '✓' "$out" || ok=false
    assert_match "log_success message on stdout" 'success message' "$out" || ok=false

    out="$(log_warn "warn message" 2>/dev/null)"
    if [[ -n "$out" ]]; then
        echo "    log_warn leaked to stdout: $(printf '%q' "$out")"
        ok=false
    fi
    err="$(log_warn "warn message" 2>&1 >/dev/null)"
    assert_match "log_warn icon on stderr" '⚠' "$err" || ok=false
    assert_match "log_warn message on stderr" 'warn message' "$err" || ok=false

    out="$(log_error "error message" 2>/dev/null)"
    if [[ -n "$out" ]]; then
        echo "    log_error leaked to stdout: $(printf '%q' "$out")"
        ok=false
    fi
    err="$(log_error "error message" 2>&1 >/dev/null)"
    assert_match "log_error icon on stderr" '✗' "$err" || ok=false
    assert_match "log_error message on stderr" 'error message' "$err" || ok=false

    record "log helpers keep icon+message on one stream" "$ok"
}

test_sourceable() {
    # main() must not run when the script is sourced. Two checks:
    #
    # 1. Functional probe (the real regression test): source the script
    #    with arguments in a fresh bash. With the BASH_SOURCE guard intact,
    #    main() stays dormant and the probe prints exactly "SOURCED-OK".
    #    Without the guard, main() would run, dispatch on the args
    #    (--version exits 0 after printing a banner), and the probe output
    #    would differ -- so removing the guard from gh-amp fails here.
    #
    # 2. Symbol check: gh-amp's main must be defined after sourcing. This
    #    only works because this suite's own entrypoint is named
    #    run_suite() -- a suite-level main() would shadow the sourced one
    #    and make declare -F main vacuously true.
    local ok=true
    local probe
    probe="$(bash -c 'source "$1" --version; echo SOURCED-OK' probe "$AMP" 2>/dev/null)" || ok=false
    if [[ "$probe" != "SOURCED-OK" ]]; then
        echo "    sourcing gh-amp ran main() or failed; probe output: $(printf '%q' "$probe")"
        ok=false
    fi
    if ! declare -F main >/dev/null; then
        echo "    gh-amp main() not defined after sourcing"
        ok=false
    fi
    record "main() dormant when sourced" "$ok"
}

run_suite() {
    echo -e "${T_BLUE}Running gh-amp function tests...${T_NORMAL}"
    echo

    test_sanitize
    test_valid_menu_choice
    test_resolve_owner_repo
    test_lookup_check_status
    test_batch_pr_number_filter
    test_color_for_status
    test_display_inert
    test_log_streams
    test_sourceable

    echo
    echo -e "Results: ${T_GREEN}$passed passed${T_NORMAL}, ${T_RED}$failed failed${T_NORMAL}"

    if (( failed > 0 )); then
        exit 1
    fi
}

run_suite "$@"
