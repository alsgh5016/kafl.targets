#!/usr/bin/env python3
"""
Fix expired vagrant/vagrant credentials in the kafl_windows Vagrant box.

Root cause: Windows local account password expires after 42 days (default
policy).  The authoritative per-user flag is PWNOEXP (bit 0x0200) in the
Account Control Block (ACB) stored at offset 0x38 in the per-user F value
(SAM\\Domains\\Account\\Users\\<RID>\\F).  The V value contains encrypted
hash blobs and string data — the ACB is NOT in the V value.

This script:
  1. Sets PWNOEXP in the ACB of the per-user F value (primary fix).
  2. Also zeroes MaxPasswordAge in the domain F value (belt-and-suspenders).

Usage: python3 fix_box_password.py <sam_path>
"""

import struct
import sys


# ---------------------------------------------------------------------------
# Minimal REGF hive parser (no external dependencies)
# ---------------------------------------------------------------------------

class RegHive:
    BASE = 0x1000  # hive bins start

    def __init__(self, path):
        with open(path, 'rb') as f:
            self.buf = bytearray(f.read())
        assert self.buf[:4] == b'regf', f"{path}: not a registry hive"
        self.path = path
        self.root_off = struct.unpack_from('<i', self.buf, 0x24)[0]

    def _abs(self, off):
        # Each cell is prefixed with a 4-byte size; skip it.
        return self.BASE + off + 4

    def _nk(self, off):
        a = self._abs(off)
        assert self.buf[a:a+2] == b'nk', \
            f"expected nk at {hex(a)}, got {self.buf[a:a+2]!r}"
        nlen  = struct.unpack_from('<H', self.buf, a + 0x48)[0]
        flags = struct.unpack_from('<H', self.buf, a + 0x02)[0]
        enc   = 'ascii' if flags & 0x20 else 'utf-16le'
        name  = self.buf[a+0x4C : a+0x4C+nlen].decode(enc, errors='replace')
        return dict(
            a      = a,
            name   = name,
            nsub   = struct.unpack_from('<I', self.buf, a + 0x14)[0],
            suboff = struct.unpack_from('<i', self.buf, a + 0x1C)[0],
            nval   = struct.unpack_from('<I', self.buf, a + 0x24)[0],
            valoff = struct.unpack_from('<i', self.buf, a + 0x28)[0],
        )

    def _children(self, node):
        if node['nsub'] == 0 or node['suboff'] < 0:
            return {}
        la  = self._abs(node['suboff'])
        sig = bytes(self.buf[la:la+2])
        result = {}

        def _add(base, step):
            n = struct.unpack_from('<H', self.buf, base + 2)[0]
            for i in range(n):
                ko = struct.unpack_from('<i', self.buf, base + 4 + i * step)[0]
                if ko < 0:
                    continue
                c = self._nk(ko)
                result[c['name'].upper()] = c

        if sig in (b'lf', b'lh'):
            _add(la, 8)
        elif sig == b'li':
            _add(la, 4)
        elif sig == b'ri':
            n = struct.unpack_from('<H', self.buf, la + 2)[0]
            for i in range(n):
                slo = struct.unpack_from('<i', self.buf, la + 4 + i * 4)[0]
                if slo < 0:
                    continue
                sla  = self._abs(slo)
                ssig = bytes(self.buf[sla:sla+2])
                if ssig in (b'lf', b'lh'):
                    _add(sla, 8)
                elif ssig == b'li':
                    _add(sla, 4)
        return result

    def navigate(self, path):
        node = self._nk(self.root_off)
        for part in path.upper().split('\\'):
            subs = self._children(node)
            if part not in subs:
                raise KeyError(f"'{part}' not found (available: {list(subs)})")
            node = subs[part]
        return node

    def _get_vinfo(self, node, name):
        if node['nval'] == 0 or node['valoff'] < 0:
            return None
        va = self._abs(node['valoff'])
        for i in range(node['nval']):
            vk_off = struct.unpack_from('<i', self.buf, va + i * 4)[0]
            if vk_off < 0:
                continue
            vka = self._abs(vk_off)
            if self.buf[vka:vka+2] != b'vk':
                continue
            vnlen   = struct.unpack_from('<H', self.buf, vka +  2)[0]
            raw_len = struct.unpack_from('<I', self.buf, vka +  4)[0]
            doff    = struct.unpack_from('<i', self.buf, vka +  8)[0]
            vflags  = struct.unpack_from('<H', self.buf, vka + 16)[0]
            enc     = 'ascii' if vflags & 1 else 'utf-16le'
            vname   = self.buf[vka+20 : vka+20+vnlen].decode(enc, errors='replace')
            if vname.upper() == name.upper():
                return dict(
                    vka    = vka,
                    dlen   = raw_len & 0x7FFF_FFFF,
                    doff   = doff,
                    inline = bool(raw_len & 0x8000_0000),
                )
        return None

    def _data_start(self, v):
        return v['vka'] + 8 if v['inline'] else self._abs(v['doff'])

    def get_data(self, node, name):
        v = self._get_vinfo(node, name)
        assert v is not None, f"value '{name}' not found"
        a = self._data_start(v)
        return bytes(self.buf[a : a + v['dlen']]), v

    def patch(self, v, offset, data):
        a = self._data_start(v) + offset
        self.buf[a : a + len(data)] = data

    def save(self):
        with open(self.path, 'wb') as f:
            f.write(self.buf)


# ---------------------------------------------------------------------------
# Fix 0: repair V value corruption from earlier incorrect patches
# ---------------------------------------------------------------------------

def repair_v_corruption(h):
    """
    Repair V value corruption left by earlier incorrect ACB-scan patches.

    Previous versions of this script scanned the V value for an ACB and
    wrote PWNOEXP (0x0200) into whatever WORD they found, corrupting:

      1. NT/LM hash blob length fields:
         tag=0x0002, rev=0x0002, len=0x10 → len=0x210 (16→528)
         This breaks NTLM authentication entirely.

      2. Triplet header length fields in the first 0xCC bytes:
         e.g. comment-length DWORD 0x00000018 → 0x00000218

    Detection for (1): scan for tag/rev=0x0002/0x0002 blobs with len > 32.
    Detection for (2): 4-byte-aligned DWORDs in [0, 0xCC) where byte[1]=0x02,
                       bytes[2-3]=0x00, and byte[0] is a small non-zero value.
    """
    rid_keys = ['000003E8']
    try:
        users_node = h.navigate('SAM\\Domains\\Account\\Users')
        for name in h._children(users_node):
            if name != 'NAMES' and name not in rid_keys:
                rid_keys.append(name)
    except KeyError:
        pass

    any_repaired = False
    for rid in rid_keys:
        try:
            user_node = h.navigate(f'SAM\\Domains\\Account\\Users\\{rid}')
            data, vv = h.get_data(user_node, 'V')
        except Exception:
            continue

        # Repair 1: hash blob lengths (scan full V value for tag+rev signature)
        for off in range(0, len(data) - 7):
            if bytes(data[off:off+4]) != b'\x02\x00\x02\x00':
                continue
            blob_len = struct.unpack_from('<I', data, off + 4)[0]
            if blob_len <= 32:
                continue
            correct = blob_len & 0xFF
            if correct not in (0, 16, 20, 24, 32):
                print(f"  [{rid}] V hash blob at 0x{off:03x}: "
                      f"unexpected len=0x{blob_len:x}, skipping")
                continue
            h.patch(vv, off + 4, struct.pack('<I', correct))
            print(f"  [{rid}] V hash blob 0x{off:03x}: "
                  f"len 0x{blob_len:x} -> 0x{correct:x} (repaired)")
            any_repaired = True

        # Repair 2: triplet header length fields (4-byte-aligned, first 0xCC bytes)
        for off in range(0, min(0xCC, len(data) - 3), 4):
            dword = struct.unpack_from('<I', data, off)[0]
            b0 = dword & 0xFF
            b1 = (dword >> 8) & 0xFF
            b2 = (dword >> 16) & 0xFF
            b3 = (dword >> 24) & 0xFF
            if b1 == 0x02 and b2 == 0 and b3 == 0 and 0 < b0 <= 0x50:
                h.patch(vv, off, struct.pack('<I', b0))
                print(f"  [{rid}] V triplet 0x{off:03x}: "
                      f"0x{dword:08x} -> 0x{b0:02x} (repaired)")
                any_repaired = True

    if not any_repaired:
        print("  No V value corruption detected")
    return any_repaired


# ---------------------------------------------------------------------------
# Fix 1: set PWNOEXP flag in the per-user F value ACB (primary fix)
# ---------------------------------------------------------------------------

def fix_user_acb_f(h):
    """
    Set PWNOEXP (0x0200) and clear lockout (0x0400) in the per-user F value.

    The user F value (SAM\\Domains\\Account\\Users\\<RID>\\F) is a fixed-length
    binary that holds account metadata: logon timestamps, RID, and the ACB.
    The ACB is a WORD at offset 0x38 (with 0x3A as fallback for some builds).

    The V value contains encrypted hash blobs and variable-length string data.
    The 0x0010 that appears in the V value is the NT-hash-blob length field
    (tag=0x0002, rev=0x0002, len=0x0010) — NOT the ACB.
    """
    rid_keys = ['000003E8']  # standard vagrant RID (1000 decimal)

    try:
        users_node = h.navigate('SAM\\Domains\\Account\\Users')
        for name in h._children(users_node):
            if name != 'NAMES' and name not in rid_keys:
                rid_keys.append(name)
    except KeyError:
        pass

    print(f"  RIDs found: {rid_keys}")

    for rid in rid_keys:
        try:
            user_node = h.navigate(f'SAM\\Domains\\Account\\Users\\{rid}')
        except KeyError:
            print(f"  [{rid}] subkey not found")
            continue

        try:
            data, fv = h.get_data(user_node, 'F')
        except (AssertionError, KeyError) as e:
            print(f"  [{rid}] F value not found: {e}")
            continue

        if len(data) < 0x40:
            print(f"  [{rid}] F value too short ({len(data)} bytes)")
            continue

        print(f"  [{rid}] F: {len(data)} bytes")
        for row in range(0, min(0x50, len(data)), 16):
            chunk = data[row:row+16]
            print(f"  [{rid}]   {row:03x}: {' '.join(f'{b:02x}' for b in chunk)}")

        # ACB is at 0x38; fall back to 0x3A for older builds
        acb_off = 0x38
        acb = struct.unpack_from('<H', data, acb_off)[0]
        if not (acb & 0x0010) or (acb & 0x01C0):
            acb_off = 0x3A
            acb = struct.unpack_from('<H', data, acb_off)[0]

        print(f"  [{rid}] ACB at F[0x{acb_off:02x}] = 0x{acb:04x}")

        if not (acb & 0x0010) or (acb & 0x01C0):
            print(f"  [{rid}] Skipping — neither 0x38 nor 0x3A looks like a normal user ACB")
            continue

        new_acb = (acb | 0x0200) & ~0x0400
        if new_acb == acb:
            print(f"  [{rid}] PWNOEXP already set (ACB=0x{acb:04x})")
        else:
            h.patch(fv, acb_off, struct.pack('<H', new_acb))
            print(f"  [{rid}] ACB: 0x{acb:04x} -> 0x{new_acb:04x}  "
                  f"(PWNOEXP set, lockout cleared at F[0x{acb_off:02x}])")
        return True

    print("  WARNING: could not find a normal user account in F values")
    return False


# ---------------------------------------------------------------------------
# Fix 2: zero MaxPasswordAge in domain F (belt-and-suspenders)
# ---------------------------------------------------------------------------

def fix_domain_maxpwdage(h):
    """
    Zero the MaxPasswordAge field in SAM\\Domains\\Account\\F.
    Offset 0x18 confirmed empirically (value = -42 days on a fresh box).
    Setting to 0x8000000000000000 (MS-SAMR sentinel for 'no max age').
    """
    account = h.navigate('SAM\\Domains\\Account')
    data, v  = h.get_data(account, 'F')

    before = data[0x18:0x20].hex()
    NEVER  = b'\x00\x00\x00\x00\x00\x00\x00\x80'  # 0x8000000000000000 LE
    h.patch(v, 0x18, NEVER)
    after  = h.get_data(account, 'F')[0][0x18:0x20].hex()
    print(f"  MaxPasswordAge: {before} -> {after}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    sam_path = sys.argv[1] if len(sys.argv) > 1 else \
               '/mnt/win/Windows/System32/config/SAM'

    h = RegHive(sam_path)

    print("[0] Repairing V value corruption from previous bad patches...")
    repair_v_corruption(h)

    print("[1] Setting PWNOEXP flag in per-user F value ACB...")
    fix_user_acb_f(h)

    print("[2] Zeroing domain MaxPasswordAge...")
    fix_domain_maxpwdage(h)

    h.save()
    print("SAM patched OK.")


if __name__ == '__main__':
    main()
