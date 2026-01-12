from Crypto.Util.number import *
from Crypto.Cipher import AES
from hashlib import sha256
import random
from pwn import *
import ast

p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
K = GF(p)
a = K(0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc)
b = K(0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b)
E = EllipticCurve(K, (a, b))
G = E(0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296, 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5)
E.set_order(0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551 * 0x1)


def h(m):
    return bytes_to_long(sha256(str(m).encode()).digest())+1

hs = list(map(h, range(25000)))


bestScore = Infinity
# This might take a couple minutes depending on your luck, but shouldn't take an unreasonable amount of time.
while bestScore>=670:
    smpl = random.sample(hs, k=72)
    M = Matrix(smpl+[2^256]).stack(Matrix.identity(n=72, ring=ZZ).augment(Matrix.zero(ncols=1, nrows=72, ring=ZZ))).stack(Matrix([1]*72+[0])).stack(Matrix.zero(ncols=73, nrows=1, ring=ZZ)).transpose().LLL().transpose()
    i = 50
    while i<90:
        L = M.augment(Matrix([-140]+[i]*72+[480]+[2000]).transpose())
        r = L.transpose()[-1]-L.transpose().LLL()[-1]
        if min(r[1:])>=0:
            break
        i+=1
    if min(r[1:])<0:
        continue
    score = r[-2]-r[0]
    if score<bestScore:
        bestSample = smpl
        currBest = r
        bestScore = score
        print(bestScore)

# Results that I found previously
#currBest = (-141, 11, 2, 14, 0, 11, 3, 3, 2, 8, 3, 16, 0, 4, 8, 4, 10, 14, 4, 1, 11, 5, 2, 10, 4, 8, 18, 6, 8, 10, 1, 8, 3, 15, 14, 4, 7, 11, 7, 5, 7, 10, 9, 11, 8, 6, 12, 9, 7, 5, 6, 14, 8, 1, 8, 4, 1, 8, 5, 14, 11, 2, 8, 9, 11, 8, 8, 6, 5, 7, 8, 7, 9, 527, 0)
#ms = [2750, 589, 1517, 9453, 6036, 24186, 777, 2766, 18061, 12898, 1434, 3651, 12543, 20801, 17322, 10836, 10624, 15049, 2833, 2575, 3344, 7517, 17117, 16166, 20034, 3195, 18402, 14822, 21774, 23054, 12096, 25481, 21916, 23835, 11176, 9735, 7081, 22247, 24545, 199, 21195, 18450, 2569, 10127, 4787, 6900, 7466, 14917, 7372, 10720, 2804, 7065, 12684, 2487, 797, 18081, 14525, 12133, 8289, 2608, 6941, 21694, 426, 8572, 16433, 12490, 19860, 6126, 8880, 7480, 8547, 21743]

ms = list(map(hs.index, bestSample))
freqs = currBest[1:-2]
exchanges = -currBest[0]+1

print(ms)
print(freqs)
print(exchanges)

io = remote("104.196.21.25", 5000)
io.readline()
io.readline()
io.readline()
print(io.readline())
io.recvuntil(b'Solution? ')
POW = input()
io.sendline(POW.encode())
io.readline()
pub = ast.literal_eval(io.readline().decode().strip())

sigs = []

for m, f in zip(ms, freqs):
    m = str(m).encode()
    for j in range(f):
        io.sendline(b'sign')
        io.sendline(m)
        r, s = list(map(int, io.readline().strip().decode().split()[-2:]))
        sigs.append((r,s))

for i in range(exchanges):
    io.sendline(b'exchange')
    sigs.append(bytes.fromhex(io.readline().strip().decode().split()[-1]))



r, s = sigs[0]
z = h(ms[0])-1

R = E.lift_x(Integer(r))
for R in (R, -R):
    S = (s*R-z*G)*pow(r, -1, E.order())
    print(AES.new(long_to_bytes(int(S.x())%(2**128), blocksize=16), AES.MODE_CBC, iv=long_to_bytes(int(S.x())>>128, blocksize=16)).decrypt(sigs[-1]))
    
