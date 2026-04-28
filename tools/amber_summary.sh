#!/bin/bash
# amber_summary.sh — single-host amber sample stats
#
# Usage: ./amber_summary.sh [batch_results_dir]
#        default: /root/kUnpack/kafl/examples/windows_x86_64/batch_results

BATCH_DIR="${1:-/root/kUnpack/kafl/examples/windows_x86_64/batch_results}"

if [ ! -d "$BATCH_DIR" ]; then
    echo "ERROR: batch dir not found: $BATCH_DIR" >&2
    exit 1
fi

printf "%-30s %6s | %5s %5s %5s %5s | %5s %5s | %s\n" \
    "SAMPLE" "DUMPS" "ALLOC" "PROT" "LDR" "MAP" "UNTRK" "DYNREG" "MAIN_RIP"
printf '%.0s-' {1..120}; echo

for dir in "$BATCH_DIR"/amber_*; do
    [ -d "$dir" ] || continue
    sample=$(basename "$dir")

    # dump count (excluding fulldump_000_ep_initial_packed)
    dumps=$(ls "$dir/dump/" 2>/dev/null | grep -c "fulldump_00[1-9]\|fulldump_0[1-9][0-9]")

    log="$dir/qemu_stderr.log"
    if [ -f "$log" ]; then
        alloc=$(grep -c "NtAllocate OK" "$log")
        prot=$(grep -c "NtProtect+EXEC" "$log")
        ldr=$(grep -c "LdrLoadDll OK" "$log")
        map=$(grep -c "NtMapView OK" "$log")
        untrk=$(grep -c "Untracked GFN" "$log")
        dynreg=$(grep -c "WtE]\[DYN-REG\]" "$log")
    else
        alloc=0; prot=0; ldr=0; map=0; untrk=0; dynreg=0
    fi

    # main entry candidate — first dump in 0x7f or other dynamic region
    # (after the initial ntdll dumps fulldump_001/002)
    main_rip=$(ls "$dir/dump/" 2>/dev/null \
        | grep -oE "fulldump_00[3-9]_wte_rip0x[0-9a-f]+_va0x[0-9a-f]+" \
        | head -1 \
        | sed 's/fulldump_/[/' | sed 's/_wte_/]/')
    [ -z "$main_rip" ] && main_rip="-"

    printf "%-30s %6d | %5d %5d %5d %5d | %5d %5d | %s\n" \
        "$sample" "$dumps" "$alloc" "$prot" "$ldr" "$map" "$untrk" "$dynreg" "$main_rip"
done
