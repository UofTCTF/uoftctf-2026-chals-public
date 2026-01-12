#!/usr/local/bin/python3

import sys
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad

def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <hex_key> <plaintext...>")
        sys.exit(1)

    # arg1 = hex key
    key_hex = sys.argv[1]
    try:
        key = bytes.fromhex(key_hex)
    except ValueError:
        print("Invalid hex key")
        sys.exit(1)

    if len(key) != 16:
        sys.exit(1)

    # arg2..N = plaintext
    pt = "\n".join(sys.argv[2:]).encode()

    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)

    ct = cipher.encrypt(pad(pt, AES.block_size))

    print(iv.hex() + ct.hex())

if __name__ == "__main__":
    main()