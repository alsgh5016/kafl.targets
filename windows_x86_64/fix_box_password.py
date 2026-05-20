#!/usr/bin/env python3
"""
Patch Windows SAM hive to disable MaximumPasswordAge (no external dependencies).

The kafl_windows Vagrant box uses a Windows guest whose local account password
expires after 42 days (Windows default policy).  This script sets
MaximumPasswordAge to 0 (unlimited) in the offline SAM hive so that the
vagrant/vagrant WinRM credentials work indefinitely.

Usage (called by fix_box_password.sh, not directly):
    python3 fix_box_password.py <sam_path>
"""

import struct
import sys


class RegHive:
    BASE = 0x1000  # hive bins start offset

    def __init__(self, path):
        with open(path, 'rb') as f:
            self.buf = bytearray(f.read())
        assert self.buf[:4] == b'regf', f"{path}: not a registry hive"
        self.path = path
        self.root_off = struct.unpack_from('<i', self.buf, 0x24)[0]

    def _abs(self, off):
        # Each cell is prefixed with a 4-byte size field; skip it.
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
        la   = self._abs(node['suboff'])
        sig  = bytes(self.buf[la:la+2])
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
                raise KeyError(f"key '{part}' not found (available: {list(subs)})")
            node = subs[part]
        return node

    def _get_value(self, node, name):
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

    def _data_abs(self, v):
        return v['vka'] + 8 if v['inline'] else self._abs(v['doff'])

    def get_data(self, node, name):
        v = self._get_value(node, name)
        assert v is not None, f"value '{name}' not found"
        a = self._data_abs(v)
        return bytes(self.buf[a : a + v['dlen']]), v

    def patch(self, v, offset, data):
        a = self._data_abs(v) + offset
        self.buf[a : a + len(data)] = data

    def save(self):
        with open(self.path, 'wb') as f:
            f.write(self.buf)


def main():
    sam_path = sys.argv[1] if len(sys.argv) > 1 else \
               '/mnt/win/Windows/System32/config/SAM'

    h       = RegHive(sam_path)
    account = h.navigate('SAM\\Domains\\Account')
    data, v = h.get_data(account, 'F')

    before = data[0x18:0x20].hex()
    # MaximumPasswordAge at offset 0x18 (8-byte negative FILETIME interval).
    # Setting to 0 disables the expiry policy for all local accounts.
    h.patch(v, 0x18, b'\x00' * 8)
    after  = h.get_data(account, 'F')[0][0x18:0x20].hex()

    print(f"  MaximumPasswordAge: {before} -> {after}")
    h.save()
    print("  SAM patched OK.")


if __name__ == '__main__':
    main()
