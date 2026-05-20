#!/usr/bin/env bash
# fix_box_password.sh — Fix expired vagrant/vagrant credentials in the kafl_windows box.
#
# The Windows guest enforces a 42-day password expiry by default.  After that
# period WinRM authentication fails and `vagrant up` cannot connect.  This
# script patches the offline SAM hive to disable MaximumPasswordAge, then
# resets the NT hash via virt-customize so vagrant/vagrant works indefinitely.
#
# Usage:
#   sudo bash fix_box_password.sh [BOX_IMG]
#
# BOX_IMG defaults to ~/.vagrant.d/boxes/kafl_windows/0/libvirt/box_0.img

set -euo pipefail

BOX_IMG="${1:-${HOME}/.vagrant.d/boxes/kafl_windows/0/libvirt/box_0.img}"
MOUNT_PT="/mnt/win"
NBD_DEV="/dev/nbd0"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

die() { echo "[ERROR] $*" >&2; exit 1; }
info() { echo "[INFO ] $*"; }

# ── pre-flight ────────────────────────────────────────────────────────────────
[[ -f "$BOX_IMG" ]] || die "Box image not found: $BOX_IMG"
[[ $EUID -eq 0 ]]   || die "Run as root (sudo)"

# ── release any existing lock on the image ───────────────────────────────────
existing=$(fuser "$BOX_IMG" 2>/dev/null || true)
if [[ -n "$existing" ]]; then
    info "Releasing existing lock (PID $existing)..."
    qemu-nbd --disconnect "$NBD_DEV" 2>/dev/null || true
    kill "$existing" 2>/dev/null || true
    sleep 1
fi

# ── load nbd module ──────────────────────────────────────────────────────────
modprobe nbd max_part=8

# ── connect image ────────────────────────────────────────────────────────────
info "Connecting $BOX_IMG -> $NBD_DEV"
qemu-nbd --connect="$NBD_DEV" "$BOX_IMG"
partprobe "$NBD_DEV" 2>/dev/null || true

cleanup() {
    info "Cleaning up..."
    umount "$MOUNT_PT" 2>/dev/null || true
    qemu-nbd --disconnect "$NBD_DEV" 2>/dev/null || true
}
trap cleanup EXIT

# ── find Windows partition (single-partition layout: p1) ─────────────────────
PART="${NBD_DEV}p1"
mkdir -p "$MOUNT_PT"
info "Mounting $PART -> $MOUNT_PT"
mount "$PART" "$MOUNT_PT"

# ── patch SAM: disable MaximumPasswordAge ────────────────────────────────────
info "Patching SAM..."
python3 "$SCRIPT_DIR/fix_box_password.py" \
    "$MOUNT_PT/Windows/System32/config/SAM"

# ── unmount before virt-customize (needs exclusive access) ───────────────────
info "Unmounting..."
umount "$MOUNT_PT"
qemu-nbd --disconnect "$NBD_DEV"
trap - EXIT

# ── reset NT hash via virt-customize (handles SYSKEY encryption) ─────────────
info "Resetting vagrant password via virt-customize..."
virt-customize -a "$BOX_IMG" --password vagrant:password:vagrant

info "Done. The kafl_windows box now has a non-expiring vagrant/vagrant credential."
