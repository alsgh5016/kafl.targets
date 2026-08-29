#!/usr/bin/env bash
# host_diag.sh — one-shot evidence collection for the "QEMU dies at Nyx
# handshake after 1-2 samples / KVM module looks dead" incident.
#
# Run on a dump server (needs sudo for dmesg / /proc/<pid>/stack / debugfs):
#   sudo bash host_diag.sh [KAFL_WORKDIR_ROOT] > host_diag_$(hostname).txt 2>&1
#
# It is read-only: it never kills processes or touches modules.
set -u
WORKROOT="${1:-}"
# Repo root: dir containing kafl.linux/ (server layout: ~/kUnpack/kafl/{kafl.linux,qemu,examples})
REPO_ROOT="${REPO_ROOT:-}"
if [ -z "$REPO_ROOT" ]; then
  for c in "$(cd "$(dirname "$0")/../.." 2>/dev/null && pwd)" "$HOME/kUnpack/kafl" "$HOME/kUnpack"; do
    [ -d "$c/kafl.linux" ] && REPO_ROOT="$c" && break
  done
fi
# Default log root: directory of the most recently modified batch_analyze.log
if [ -z "$WORKROOT" ]; then
  WORKROOT="$(dirname "$(find /hdd /root /home -maxdepth 4 -name batch_analyze.log -printf '%T@ %p\n' 2>/dev/null | sort -n | tail -1 | cut -d' ' -f2-)" 2>/dev/null)"
fi

section() { printf '\n===== %s =====\n' "$*"; }

section "host"
hostname; date; uname -r; uptime

section "repo heads (what is deployed)"
for r in kafl.linux kafl.qemu qemu kafl.targets examples; do
  d="$REPO_ROOT/$r"
  [ -d "$d/.git" ] && printf '%-14s %s\n' "$r" "$(git -C "$d" log -1 --format='%h %ad %s' --date=short)"
done

section "kvm modules loaded (refcount) + srcversion vs built .ko"
lsmod | grep -E '^(kvm|kvm_intel|irqbypass|vhost)' || echo "!! no kvm modules loaded"
for m in kvm kvm_intel; do
  live=$(cat /sys/module/$m/srcversion 2>/dev/null || echo none)
  ko="$REPO_ROOT/kafl.linux/arch/x86/kvm/${m/_/-}.ko"
  built=$(modinfo -F srcversion "$ko" 2>/dev/null || echo none)
  printf '%-9s live=%s built=%s %s\n' "$m" "$live" "$built" "$([ "$live" = "$built" ] && echo MATCH || echo '!! MISMATCH')"
  modinfo -F vermagic "$ko" 2>/dev/null | sed 's/^/  built vermagic: /'
done
ls -l /dev/kvm 2>&1

section "kernel log: crashes / warnings / allocation failures"
dmesg -T 2>/dev/null | grep -nE 'BUG|Oops|WARNING|Call Trace|RIP:|general protection|page allocation failure|order:[0-9]+|hung task|soft lockup|rcu_sched|refcount|ToPA|topa|vmx_pt|nyx|kvm|KVM|taint' | tail -80
section "kernel log: raw tail"
dmesg -T 2>/dev/null | tail -40

section "memory"
free -m
grep -E 'MemTotal|MemFree|MemAvailable|Buffers|^Cached|Shmem:|Slab|SReclaimable|SUnreclaim|KernelStack|PageTables|Unevictable|Mlocked|HugePages_|Hugepagesize|CommitLimit|Committed_AS' /proc/meminfo
section "buddyinfo (columns = free blocks of order 0..10; ToPA needs order-10, fallback order-4)"
cat /proc/buddyinfo
section "top slab consumers"
if command -v slabtop >/dev/null; then slabtop -o -s c 2>/dev/null | head -22; else sort -k3 -n -r /proc/slabinfo 2>/dev/null | head -20; fi

section "live KVM VMs (debugfs) — each dir is a VM still alive: <pid>-<fd>"
ls -la /sys/kernel/debug/kvm/ 2>&1 | head -40

section "qemu / kafl / libvirt processes (STAT: D=uninterruptible, Z=zombie)"
ps -eo pid,ppid,stat,etime,rss,wchan:32,comm,args --sort=start_time | grep -E 'qemu|kafl|libvirt|vagrant|batch_analyze|auto_batch' | grep -v grep | cut -c1-220

section "processes holding /dev/kvm or a kvm-vm fd"
for p in /proc/[0-9]*; do
  pid=${p#/proc/}
  fds=$(ls -l "$p/fd" 2>/dev/null | grep -cE 'kvm-vm|kvm-vcpu|/dev/kvm')
  [ "${fds:-0}" -gt 0 ] && printf 'pid=%s fds=%s stat=%s cmd=%s\n' "$pid" "$fds" "$(awk '{print $3}' "$p/stat" 2>/dev/null)" "$(tr '\0' ' ' < "$p/cmdline" | cut -c1-120)"
done

section "kernel stacks of D-state / zombie qemu processes"
for pid in $(ps -eo pid,stat,comm | awk '$2 ~ /^[DZ]/ && $3 ~ /qemu/ {print $1}'); do
  echo "--- pid $pid"; cat /proc/$pid/wchan 2>/dev/null; echo; cat /proc/$pid/stack 2>/dev/null
done

section "libvirt domains"
virsh list --all 2>/dev/null | head

section "kafl logs: last error lines"
if [ -n "$WORKROOT" ] && [ -d "$WORKROOT" ]; then
  echo "log root: $WORKROOT"
  for f in $(find "$WORKROOT" -maxdepth 4 \( -name 'qemu_stderr.log' -o -name 'hprintf_*.log' -o -name 'serial_*.log' -o -name 'batch_analyze.log' \) -mmin -720 2>/dev/null | head -20); do
    echo "--- $f"; grep -nE 'ToPA|abort|Abort|Broken|Failed|failed|error|Error|assert|ioctl|Workers aborted' "$f" | tail -15
  done
else
  echo "(pass the kafl workdir root as \$1 to include log tails)"
fi
