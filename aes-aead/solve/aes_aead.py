from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes, bytes_to_long
from Crypto.Util import Counter

    
def xor_block(a: bytearray, b: bytes):
    """In-place XOR: a ^= b (16 bytes)."""
    for i in range(16):
        a[i] ^= b[i]


def shift_right_block(block: bytearray):
    """Right shift a 16-byte block by 1 bit (big-endian)."""
    carry = 0
    for i in range(16):
        new_carry = block[i] & 1
        block[i] = (block[i] >> 1) | (carry << 7)
        carry = new_carry


def gf_mult(x: bytes, y: bytes) -> bytes:
    """
    Galois field multiplication GF(2^128) for GHASH:
    return x · y mod (x^128 + x^7 + x^2 + x + 1)
    Matches the reference C bit-by-bit version.
    """
    z = bytearray(16)          # Z_0
    v = bytearray(y)           # V_0

    for i in range(16):
        for j in range(8):
            if x[i] & (1 << (7 - j)):
                xor_block(z, v)

            # If LSB of V is set, shift and apply R
            if v[15] & 1:
                shift_right_block(v)
                v[0] ^= 0xe1
            else:
                shift_right_block(v)

    return bytes(z)


def ghash_start() -> bytes:
    """Return initial Y_0 = 0^128."""
    return bytearray(16)


def ghash(h: bytes, x: bytes, y: bytes) -> bytes:
    """
    GHASH(H, X) → Y
    H: 16-byte hash subkey
    X: arbitrary-length data
    """
    h = bytes(h)
    y = bytes(y)

    full_blocks = len(x) // 16
    xpos = 0

    # Process full blocks
    for _ in range(full_blocks):
        # tmp = y · H
        tmp = bytearray(gf_mult(y, h))
        # tmp ^= X_i
        xor_block(tmp, x[xpos:xpos+16])
        y = tmp
        xpos += 16

    # Process last partial block
    if xpos < len(x):
        tmp = bytearray(gf_mult(y, h))
        last = x[xpos:]

        y = bytearray(16)
        y[:len(last)] = last

        xor_block(y, tmp)
    return y


class AES_AEAD:
    def __init__(self, master_key):
        self.change_key(master_key)
    
    def change_key(self, master_key):
        self.__master_key = master_key
        self.__aes_ecb = AES.new(self.__master_key, AES.MODE_ECB)
        self.__auth_key = self.__aes_ecb.encrypt(b'\x00' * 16)

    def encrypt(self, iv, plaintext):
        
        J0 = ghash_start()
        J0 = ghash(self.__auth_key, iv, J0)
        len_buf = b'\0' * 8 + (len(iv)*8).to_bytes(8, 'big')
        J0 = ghash(self.__auth_key, len_buf, J0)

        aes_gcm = AES.new(self.__master_key, AES.MODE_CTR, counter=Counter.new(
                nbits=32,
                prefix=J0[:12],
                initial_value=bytes_to_long(J0[12:]) + 1,
                little_endian=False))

        ct=  aes_gcm.encrypt(plaintext)

        S = ghash_start()
        S = ghash(self.__auth_key, b'', S)
        S = ghash(self.__auth_key, ct, S)
        len_buf = b'\0'*8 + (len(ct)*8).to_bytes(8, 'big')
        S = bytearray(ghash(self.__auth_key, len_buf, S))

        xor_block(S, self.__aes_ecb.encrypt(J0))


        return ct, S