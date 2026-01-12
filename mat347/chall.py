from sage.all import *
from Crypto.Util.number import *
import os
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

#https://std.neuromancer.sk/nist/P-256
p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
K = GF(p)
a = K(0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc)
b = K(0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b)
E = EllipticCurve(K, (a, b))
G = E(0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296, 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5)
E.set_order(0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551 * 0x1)

x = bytes_to_long(os.urandom(32))
Q = x*G
print(Q.xy())

def h(m):
    return bytes_to_long(sha256(m.encode()).digest())

class RNG:
    def __init__(self):
        self.cnt = bytes_to_long(os.urandom(32))
        self.mod = 2**256
    def next(self, m):
        res = h(str(self.cnt))
        a = 0 if m is None else h(m)
        self.cnt = (self.cnt+1+a)%self.mod
        return res


def sign(m, rng):
    z = h(m)
    k = rng.next(m)
    r = int((k*G).x())
    s = ((pow(k, -1, E.order())*z+(x*r)))%E.order()
    return r, s

def exchange(rng):
    k = rng.next(None)
    msg = open("flag.txt", "rb").read()
    return AES.new(long_to_bytes(int((k*Q).x())%(2**128), blocksize=16), AES.MODE_CBC, iv=long_to_bytes(int((k*Q).x())>>128, blocksize=16)).encrypt(pad(msg, 16))

rng = RNG()

for z in range(670):
    choice = input("Sign or Exchange? ").lower().strip()
    if choice=="sign":
        m = input("Message: ")
        print(*sign(m, rng))
    elif choice=="exchange":
        print(exchange(rng).hex())
    else:
        print("Bad input")
