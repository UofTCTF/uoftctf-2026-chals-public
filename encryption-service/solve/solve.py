from pwn import *
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad

# not super consistent for some reason

r = remote("34.86.4.154", 5000)
for i in range(8000):
    r.sendline(b'0'*32)
r.sendline(b'0'*32)

r.sendline(b'EOF')
dat = r.recvall().split()
print(dat, len(dat))
dat = dat[-1].decode()
iv = bytes.fromhex(dat[:32])
ct = bytes.fromhex(dat[32:])

print(AES.new(b'\0'*16, AES.MODE_CBC, iv).decrypt(ct))