#!/usr/bin/env python3
# Copyright (c) 2026 The Trap Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""
Rewrite Bitcoin address and key encodings found in test sources/data into
their TRAP equivalents, keeping the underlying payload identical.

Only strings whose checksum verifies are rewritten, so deliberately corrupted
test inputs are left untouched.

  Base58Check: P2PKH version 0 -> 65, P2SH 5 -> 60, WIF 128 -> 193
  Bech32(m):   bc -> trap, tb -> ttrap, sp -> trapsp, tsp -> ttrapsp

Descriptor checksums that were valid before the rewrite are recomputed.

Usage: btc_to_trap.py FILE...   (files are rewritten in place)
"""

import hashlib
import re
import sys

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
BECH32_CONST = 1
BECH32M_CONST = 0x2bc830a3

B58_VERSIONS = {0: (65, {21}), 5: (60, {21}), 128: (193, {33, 34})}
HRPS = {"bc": "trap", "tb": "ttrap", "sp": "trapsp", "tsp": "ttrapsp"}


def dsha(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def b58decode(s):
    n = 0
    for c in s:
        n = n * 58 + B58.index(c)
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return b"\0" * (len(s) - len(s.lstrip("1"))) + raw


def b58encode(b):
    n = int.from_bytes(b, "big")
    s = ""
    while n:
        n, r = divmod(n, 58)
        s = B58[r] + s
    return "1" * (len(b) - len(b.lstrip(b"\0"))) + s


def convert_b58(s):
    data = b58decode(s)
    if len(data) < 5 or dsha(data[:-4])[:4] != data[-4:]:
        return s
    payload = data[:-4]
    mapping = B58_VERSIONS.get(payload[0])
    if mapping is None or len(payload) not in mapping[1]:
        return s
    new = bytes([mapping[0]]) + payload[1:]
    return b58encode(new + dsha(new)[:4])


def polymod(values):
    gen = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for v in values:
        top = chk >> 25
        chk = (chk & 0x1ffffff) << 5 ^ v
        for i in range(5):
            chk ^= gen[i] if ((top >> i) & 1) else 0
    return chk


def hrp_expand(hrp):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def convert_bech32(s):
    if s.lower() != s and s.upper() != s:
        return s
    upper = s.upper() == s
    low = s.lower()
    pos = low.rfind("1")
    hrp, data = low[:pos], [CHARSET.find(c) for c in low[pos + 1:]]
    if hrp not in HRPS or -1 in data or len(data) < 6:
        return s
    const = polymod(hrp_expand(hrp) + data)
    if const not in (BECH32_CONST, BECH32M_CONST):
        return s
    new_hrp = HRPS[hrp]
    payload = data[:-6]
    values = hrp_expand(new_hrp) + payload
    pm = polymod(values + [0] * 6) ^ const
    checksum = [(pm >> 5 * (5 - i)) & 31 for i in range(6)]
    out = new_hrp + "1" + "".join(CHARSET[d] for d in payload + checksum)
    return out.upper() if upper else out


B58_RE = re.compile(r"(?<![0-9A-Za-z])[1-9A-HJ-NP-Za-km-z]{26,60}(?![0-9A-Za-z])")
BECH32_RE = re.compile(r"(?<![0-9A-Za-z])(?:bc|tb|sp|tsp|BC|TB|SP|TSP)1[0-9A-Za-z]{6,}(?![0-9A-Za-z])")


INPUT_CHARSET = "0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#\"\\ "


def descsum(desc):
    """Descriptor checksum, as in test/functional/test_framework/descriptors.py."""
    def polymod40(c, val):
        c0 = c >> 35
        c = ((c & 0x7ffffffff) << 5) ^ val
        for i, g in enumerate((0xf5dee51989, 0xa9fdca3312, 0x1bab10e32d, 0x3706b1677a, 0x644d626ffd)):
            if c0 & (1 << i):
                c ^= g
        return c
    c, cls, clscount = 1, 0, 0
    for ch in desc:
        pos = INPUT_CHARSET.find(ch)
        if pos == -1:
            return None
        c = polymod40(c, pos & 31)
        cls = cls * 3 + (pos >> 5)
        clscount += 1
        if clscount == 3:
            c = polymod40(c, cls)
            cls, clscount = 0, 0
    if clscount > 0:
        c = polymod40(c, cls)
    for _ in range(8):
        c = polymod40(c, 0)
    c ^= 1
    return "".join(CHARSET[(c >> (5 * (7 - i))) & 31] for i in range(8))


def convert_plain(text):
    text = BECH32_RE.sub(lambda m: convert_bech32(m.group(0)), text)
    return B58_RE.sub(lambda m: convert_b58(m.group(0)), text)


# A descriptor followed by its checksum, e.g. addr(1A1z...)#abcdefgh
DESC_RE = re.compile(r"([a-z_]+\([^\s\"#]*\))#([" + CHARSET + r"]{8})(?![0-9a-z])")


def convert_desc(m):
    desc, checksum = m.group(1), m.group(2)
    new_desc = convert_plain(desc)
    if new_desc == desc or descsum(desc) != checksum:
        return new_desc + "#" + checksum
    return new_desc + "#" + descsum(new_desc)


def convert_text(text):
    text = DESC_RE.sub(convert_desc, text)
    return convert_plain(text)


if __name__ == "__main__":
    for path in sys.argv[1:]:
        with open(path, encoding="utf8") as f:
            old = f.read()
        new = convert_text(old)
        if new != old:
            with open(path, "w", encoding="utf8") as f:
                f.write(new)
            print(f"rewrote {path}")
