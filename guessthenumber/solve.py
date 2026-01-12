from pwn import *

MAX_NUM = 1<<100
QUOTA = 64

r = remote("localhost", 5000)

min = 0
max = MAX_NUM
for j in range(QUOTA):
    print(min, max, max-min)
    expr = {"op":"or", "arg1":{"op":"<", "arg1":"x", "arg2":(min + (max-min)//3)}, "arg2":{"op":"and", "arg1":{"op":"**", "arg1":2, "arg2":int(2**25)}, "arg2":{"op":"and", "arg1":{"op":">=", "arg1":"x", "arg2":(min + (max-min)//3)}, "arg2":{"op":"<", "arg1":"x", "arg2":(min + ((max-min)//3)*2)}}}}
    t1 = time.time()
    r.sendlineafter(b'Input your expression', str(expr))
    res = r.recvuntil(b'!')
    t2 = time.time()
    print(t2- t1, res)
    if b'No' in res:
        min = min + ((max-min)//3)*2 
        continue
   
    if t2-t1 > 0.3:
        max, min = min + ((max-min)//3)*2 - 1, min + ((max-min)//3)
        continue
    max = min + ((max-min)//3) - 1
r.interactive()
    