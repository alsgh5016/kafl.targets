#!/usr/bin/env bash
# fix_box_password.sh — Fix expired vagrant/vagrant credentials in the kafl_windows box.
#
# The Windows guest enforces a 42-day password expiry by default.  After that
# period WinRM authentication fails and `vagrant up` cannot connect.  This
# script patches the offline SAM hive to disable password expiry, then
# optionally resets the NT hash via virt-customize.
#
# It patches TWO copies of the image:
#   1. ~/.vagrant.d/boxes/kafl_windows/.../box_0.img  (vagrant source)
#   2. The libvirt storage pool base image            (what vagrant-libvirt uses)
#
# vagrant-libvirt imports box_0.img into the pool on first use and keeps it
# there across `vagrant destroy`.  Without patching the pool copy, new VMs
# still get the expired credentials.
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

die()  { echo "[ERROR] $*" >&2; exit 1; }
info() { echo "[INFO ] $*"; }

# ── pre-flight ────────────────────────────────────────────────────────────────
[[ -f "$BOX_IMG" ]] || die "Box image not found: $BOX_IMG"
[[ $EUID -eq 0 ]]   || die "Run as root (sudo)"

modprobe nbd max_part=8

# ── helpers ───────────────────────────────────────────────────────────────────

_nbd_connect() {
    local img="$1"
    local existing
    existing=$(fuser "$img" 2>/dev/null || true)
    if [[ -n "$existing" ]]; then
        info "Releasing existing lock on $img (PID $existing)..."
        qemu-nbd --disconnect "$NBD_DEV" 2>/dev/null || true
        kill "$existing" 2>/dev/null || true
        sleep 1
    fi
    qemu-nbd --connect="$NBD_DEV" "$img"
    partprobe "$NBD_DEV" 2>/dev/null || true
}

_nbd_disconnect() {
    umount "$MOUNT_PT" 2>/dev/null || true
    qemu-nbd --disconnect "$NBD_DEV" 2>/dev/null || true
}

cleanup() { _nbd_disconnect; }
trap cleanup EXIT

patch_box_image() {
    local img="$1"
    info "--- Patching: $img"

    _nbd_connect "$img"

    mkdir -p "$MOUNT_PT"
    # remove_hiberfile: clear hibernation/fast-startup flag that blocks NTFS write access
    mount -t ntfs-3g -o remove_hiberfile "${NBD_DEV}p1" "$MOUNT_PT"

    python3 "$SCRIPT_DIR/fix_box_password.py" \
        "$MOUNT_PT/Windows/System32/config/SAM"

    _nbd_disconnect
    info "--- Done: $img"
}

# ── find all libvirt pool base images for kafl_windows ───────────────────────
# vagrant-libvirt names pool volumes: kafl_windows_vagrant_box_image_0_<hash>_box_0.img
# Multiple copies can exist when the box was re-imported at different times.
find_pool_images() {
    local results=()
    # Try virsh first (authoritative)
    if command -v virsh &>/dev/null; then
        local pool vol path
        for pool in $(virsh -c qemu:///system pool-list --name 2>/dev/null || true); do
            while IFS= read -r vol; do
                [[ -z "$vol" ]] && continue
                path=$(virsh -c qemu:///system vol-path --pool "$pool" "$vol" 2>/dev/null || true)
                [[ -n "$path" && -f "$path" ]] && results+=("$path")
            done < <(virsh -c qemu:///system vol-list "$pool" 2>/dev/null \
                     | awk '/kafl_windows/ && /_box_[0-9]+\.img$/{print $1}')
        done
    fi
    # Fallback / supplement: filesystem search in common pool paths
    while IFS= read -r p; do
        # deduplicate
        local dup=0
        for r in "${results[@]+"${results[@]}"}"; do [[ "$r" == "$p" ]] && dup=1 && break; done
        [[ $dup -eq 0 ]] && results+=("$p")
    done < <(find /root/.local/share/libvirt/images \
                  /var/lib/libvirt/images \
                  "${HOME}/.local/share/libvirt/images" \
                  -name "*kafl_windows*_box_*.img" 2>/dev/null || true)
    printf '%s\n' "${results[@]+"${results[@]}"}"
}

# ── patch vagrant source box ──────────────────────────────────────────────────
info "=== [1/2] Patching vagrant source box ==="
patch_box_image "$BOX_IMG"

# ── patch all libvirt pool base images ───────────────────────────────────────
info "=== [2/2] Patching libvirt pool base images ==="
mapfile -t POOL_IMGS < <(find_pool_images || true)

patched_pool=0
for pimg in "${POOL_IMGS[@]+"${POOL_IMGS[@]}"}"; do
    [[ "$pimg" == "$BOX_IMG" ]] && continue
    info "Found pool image: $pimg"
    patch_box_image "$pimg"
    ((patched_pool++)) || true
done
[[ $patched_pool -eq 0 ]] && info "No separate pool base images found."

trap - EXIT

# ── reset NT hash via virt-customize (handles SYSKEY encryption) ─────────────
# Non-fatal: PWNOEXP patch above is the primary fix.
# virt-customize updates the NT hash + pwdLastSet as extra insurance.
info "Resetting vagrant password via virt-customize (optional)..."
vc_targets=("$BOX_IMG")
for pimg in "${POOL_IMGS[@]+"${POOL_IMGS[@]}"}"; do
    [[ "$pimg" != "$BOX_IMG" ]] && vc_targets+=("$pimg")
done

for img in "${vc_targets[@]}"; do
    info "  virt-customize: $img"
    virt-customize -a "$img" --password vagrant:password:vagrant 2>&1 || \
        info "  virt-customize: skipped (not supported on this host)."
done

info "Done. The kafl_windows box now has a non-expiring vagrant/vagrant credential."
