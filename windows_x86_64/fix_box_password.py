#!/usr/bin/env python3
"""
Fix expired vagrant/vagrant credentials in the kafl_windows Vagrant box.

Root cause: Windows local account password expires after 42 days (default
policy).  The authoritative per-user flag is PWNOEXP (bit 0x0200) in the
Account Control Block (ACB) stored unencrypted in the user's SAM V value.
MaxPasswordAge in the domain F value only applies to domain accounts, not
local ones.

This script:
  1. Sets PWNOEXP on the vagrant user's ACB so the password never expires.
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
# Fix 1: set PWNOEXP flag in vagrant user's ACB (primary fix)
# ---------------------------------------------------------------------------

def fix_user_pwnoexp(h):
    """
    Set the PasswordNeverExpires (PWNOEXP = 0x0200) bit in the vagrant
    user's Account Control Block stored in the SAM V value.

    The ACB lives in the fixed (non-encrypted) header of the V binary at
    either offset 0x38 (Windows Vista+) or 0x34 (XP/2003).  We detect the
    right offset by looking for the Normal Account flag (0x0010).

    We also clear the lockout bit (0x0400), which Windows sets after too
    many failed login attempts — a common side-effect of WinRM retries.
    """
    # Try the standard vagrant RID first (1000 = 0x3E8)
    rid_keys = ['000003E8']

    # Fallback: enumerate all user RIDs
    try:
        users_node = h.navigate('SAM\\Domains\\Account\\Users')
        for name in h._children(users_node):
            if name != 'NAMES' and name not in rid_keys:
                rid_keys.append(name)
    except KeyError:
        pass

    print(f"  RIDs found: {rid_keys}")

    acb_candidates_printed = False
    for rid in rid_keys:
        try:
            user_node = h.navigate(f'SAM\\Domains\\Account\\Users\\{rid}')
        except KeyError:
            print(f"  [{rid}] subkey not found")
            continue

        try:
            data, v = h.get_data(user_node, 'V')
        except (AssertionError, KeyError) as e:
            print(f"  [{rid}] V value not found: {e}")
            continue

        if len(data) < 0x3A:
            print(f"  [{rid}] V value too short ({len(data)} bytes)")
            continue

        # Full hex dump of V value for the first user — helps locate ACB offset
        if not acb_candidates_printed:
            print(f"  [{rid}] V: {len(data)} bytes  "
                  f"doff=0x{v['doff']:x}  inline={v['inline']}")
            for row in range(0, len(data), 16):
                chunk = data[row:row+16]
                hex_str = ' '.join(f'{b:02x}' for b in chunk)
                print(f"  [{rid}]   {row:03x}: {hex_str}")

        # Scan the ENTIRE V value for ACB candidates.
        # Filter: bit 4 (Normal Account, 0x0010) must be set;
        #         bits 6/7/8 (trust account: 0x01C0) must be clear;
        #         value < 0x0800 to exclude large offset values in the
        #         triplet descriptor header (which happen to share bit 4).
        acb_candidates = []
        for off in range(0, len(data) - 1, 2):
            val = struct.unpack_from('<H', data, off)[0]
            if (val & 0x0010) and not (val & 0x01C0) and val < 0x0800:
                acb_candidates.append((off, val))
        # Sort by value ascending: the true ACB (0x0010 for Normal Account) is the
        # minimum possible value; false positives from triplet header data are larger.
        acb_candidates.sort(key=lambda x: x[1])
        print(f"  [{rid}] ACB candidates: "
              f"{[(f'0x{o:03x}', f'0x{v_:04x}') for o, v_ in acb_candidates]}")

        acb_candidates_printed = True

        for acb_off, acb in acb_candidates:
            # Set PWNOEXP (0x0200); clear lockout (0x0400) while we're here.
            new_acb = (acb | 0x0200) & ~0x0400
            if new_acb == acb:
                print(f"  [{rid}] PWNOEXP already set at V[0x{acb_off:02x}] "
                      f"(ACB=0x{acb:04x})")
            else:
                h.patch(v, acb_off, struct.pack('<H', new_acb))
                print(f"  [{rid}] ACB: 0x{acb:04x} -> 0x{new_acb:04x}  "
                      f"(PWNOEXP set, lockout cleared at V[0x{acb_off:02x}])")
            return True

    print("  WARNING: could not locate ACB for any user — PWNOEXP not set")
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

    print("[1] Setting PWNOEXP flag on vagrant user...")
    fix_user_pwnoexp(h)

    print("[2] Zeroing domain MaxPasswordAge...")
    fix_domain_maxpwdage(h)

    h.save()
    print("SAM patched OK.")


if __name__ == '__main__':
    main()
