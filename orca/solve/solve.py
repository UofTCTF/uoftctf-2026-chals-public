#!/usr/bin/env python3
from pwn import *
import base64, os, re
from collections import Counter

context.log_level = "error"

HOST, PORT = "34.186.247.84", 5000
BS = 16
FLAG_RE = re.compile(rb"uoftctf\{[^}]+\}")

def oracle_connect():
    r = remote(HOST, PORT)
    r.recvuntil(b"> ")
    return r

def q(r, idx: int, data: bytes) -> bytes | None:
    line = f"{idx}:{data.hex()}".encode()
    r.sendline(line)
    resp = r.recvline().strip()
    r.recvuntil(b"> ")
    if resp == b"error":
        return None
    return base64.b64decode(resp)

def discover_nblocks(r, limit=256) -> int:
    for i in range(limit):
        if q(r, i, b"") is None:
            return i
    raise Exception("failed to discover nblocks")

def get_all_blocks(r, nblocks: int, data: bytes):
    return [q(r, i, data) for i in range(nblocks)]

def find_align_pad(r, nblocks: int) -> int:
    for pad in range(BS):
        pt = b"C"*pad + b"A"*(3*BS) + b"D"*BS
        bl = get_all_blocks(r, nblocks, pt)
        c = Counter(bl)
        if any(v >= 3 for v in c.values()):
            return pad
    raise Exception("align_pad not found")

def find_marker_ct(r, nblocks: int, align_pad: int, marker=b"Z"*BS) -> bytes:
    pt = b"C"*align_pad + marker + os.urandom(BS) + marker + os.urandom(BS)
    bl = get_all_blocks(r, nblocks, pt)
    c = Counter(bl)
    dups = [b for b, v in c.items() if v >= 2]
    if not dups:
        raise Exception("marker_ct not found")
    dups.sort(key=lambda x: c[x], reverse=True)
    return dups[0]

def find_out_index_for_t(r, nblocks: int, align_pad: int, marker_ct: bytes, t: int, marker=b"Z"*BS) -> int:
    pt = b"C"*align_pad + os.urandom(BS*t) + marker + os.urandom(BS*2)
    for i in range(nblocks):
        b = q(r, i, pt)
        if b == marker_ct:
            return i
    raise Exception("failed to locate marker output index")

def solve():
    r = oracle_connect()
    nblocks = discover_nblocks(r)
    align_pad = find_align_pad(r, nblocks)
    marker_ct = find_marker_ct(r, nblocks, align_pad)

    pos_cache = {}
    recovered = b""
    i = 0

    while True:
        fill = BS - 1 - (i % BS)
        t = (fill + i) // BS

        if t not in pos_cache:
            pos_cache[t] = find_out_index_for_t(r, nblocks, align_pad, marker_ct, t)
        idx = pos_cache[t]

        target = q(r, idx, b"C"*align_pad + b"A"*fill)
        if target is None:
            raise Exception("unexpected error on probe")

        base = b"C"*align_pad + b"A"*fill + recovered
        found = None
        for g in range(256):
            b = q(r, idx, base + bytes([g]))
            if b == target:
                found = g
                break

        if found is None:
            raise Exception(f"dictionary miss at byte {i}")

        recovered += bytes([found])
        i += 1

        print(f"Recovered {i} bytes: {recovered!r}")

        m = FLAG_RE.search(recovered)
        if m:
            print(m.group(0).decode())
            return

if __name__ == "__main__":
    solve()
