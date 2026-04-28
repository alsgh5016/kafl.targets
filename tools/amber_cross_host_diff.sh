#!/bin/bash
# amber_cross_host_diff.sh — compare amber results between two hosts
#
# Each host's batch_results dir is rsync'd to local, then run:
#   ./amber_cross_host_diff.sh <iMac3_dir> <iMacPro_dir>
#
# Comparison ignores ASLR base — looks at:
#   * dump count delta
#   * main-entry RIP page-offset (lower 12 bits) match across hosts
#   * % of unique page-offsets that appear in both host dumps

H1_DIR="${1:?usage: $0 <host1_results> <host2_results>}"
H2_DIR="${2:?usage: $0 <host1_results> <host2_results>}"
H1_NAME=$(basename "$H1_DIR")
H2_NAME=$(basename "$H2_DIR")

extract_offsets() {
    # extract last 3 hex chars of each dump RIP (= offset within page)
    ls "$1/dump/" 2>/dev/null \
        | grep -oE "rip0x[0-9a-f]+_va0x[0-9a-f]+" \
        | grep -oE "rip0x[0-9a-f]+" \
        | grep -oE "[0-9a-f]{3}$" \
        | sort -u
}

extract_va_pages() {
    # extract va page (skip ntdll dumps starting with 0x77)
    ls "$1/dump/" 2>/dev/null \
        | grep -oE "va0x[0-9a-f]+" \
        | sort -u
}

extract_main_offset() {
    # main entry candidate — first dump after fulldump_000-002 (those are ntdll)
    ls "$1/dump/" 2>/dev/null \
        | grep -oE "fulldump_00[3-9]_wte_rip0x[0-9a-f]+" \
        | head -1 \
        | grep -oE "rip0x[0-9a-f]+" \
        | grep -oE "[0-9a-f]{3,5}$"
}

printf "%-30s | %s vs %s\n" "SAMPLE" "$H1_NAME" "$H2_NAME"
printf "%-30s | %-12s %-15s %-15s %s\n" \
    "" "DUMP_COUNT" "MAIN_OFFSET" "OFFSET_INTERSECT" "VERDICT"
printf '%.0s-' {1..110}; echo

for dir in "$H1_DIR"/amber_*; do
    [ -d "$dir" ] || continue
    sample=$(basename "$dir")
    [ -d "$H2_DIR/$sample" ] || continue

    h1_dumps=$(ls "$dir/dump/" 2>/dev/null | grep -c "fulldump_00[1-9]\|fulldump_0[1-9][0-9]")
    h2_dumps=$(ls "$H2_DIR/$sample/dump/" 2>/dev/null | grep -c "fulldump_00[1-9]\|fulldump_0[1-9][0-9]")

    h1_main=$(extract_main_offset "$dir")
    h2_main=$(extract_main_offset "$H2_DIR/$sample")
    if [ -n "$h1_main" ] && [ "$h1_main" = "$h2_main" ]; then
        main_str="MATCH ($h1_main)"
    elif [ -n "$h1_main" ] && [ -n "$h2_main" ]; then
        main_str="DIFF ($h1_main/$h2_main)"
    else
        main_str="NONE"
    fi

    h1_off=$(mktemp)
    h2_off=$(mktemp)
    extract_offsets "$dir" > "$h1_off"
    extract_offsets "$H2_DIR/$sample" > "$h2_off"
    common=$(comm -12 "$h1_off" "$h2_off" | wc -l)
    h1_total=$(wc -l < "$h1_off")
    h2_total=$(wc -l < "$h2_off")
    rm "$h1_off" "$h2_off"
    union=$((h1_total + h2_total - common))
    pct=0
    [ "$union" -gt 0 ] && pct=$((common * 100 / union))

    # verdict: how good is cross-host match
    if [ "$main_str" = "NONE" ]; then
        verdict="NO_DUMP"
    elif [[ "$main_str" == MATCH* ]] && [ "$pct" -ge 80 ]; then
        verdict="GOOD"
    elif [[ "$main_str" == MATCH* ]] && [ "$pct" -ge 50 ]; then
        verdict="OK"
    elif [[ "$main_str" == MATCH* ]]; then
        verdict="MAIN_OK"
    else
        verdict="DIVERGENT"
    fi

    printf "%-30s | %5d/%-5d %-15s %5d/%-3d (%2d%%)  %s\n" \
        "$sample" "$h1_dumps" "$h2_dumps" \
        "$main_str" "$common" "$union" "$pct" "$verdict"
done

# Aggregate stats at the end
echo
echo "=== Verdict distribution ==="
for dir in "$H1_DIR"/amber_*; do
    [ -d "$dir" ] || continue
    sample=$(basename "$dir")
    [ -d "$H2_DIR/$sample" ] || continue
    h1_main=$(extract_main_offset "$dir")
    h2_main=$(extract_main_offset "$H2_DIR/$sample")
    h1_off=$(mktemp)
    h2_off=$(mktemp)
    extract_offsets "$dir" > "$h1_off"
    extract_offsets "$H2_DIR/$sample" > "$h2_off"
    common=$(comm -12 "$h1_off" "$h2_off" | wc -l)
    h1_total=$(wc -l < "$h1_off")
    h2_total=$(wc -l < "$h2_off")
    rm "$h1_off" "$h2_off"
    union=$((h1_total + h2_total - common))
    pct=0
    [ "$union" -gt 0 ] && pct=$((common * 100 / union))

    if [ -z "$h1_main" ] && [ -z "$h2_main" ]; then echo "NO_DUMP"
    elif [ "$h1_main" = "$h2_main" ] && [ "$pct" -ge 80 ]; then echo "GOOD"
    elif [ "$h1_main" = "$h2_main" ] && [ "$pct" -ge 50 ]; then echo "OK"
    elif [ "$h1_main" = "$h2_main" ]; then echo "MAIN_OK"
    else echo "DIVERGENT"
    fi
done | sort | uniq -c | sort -rn
