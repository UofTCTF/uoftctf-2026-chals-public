from pwn import *

MAX_NUM = 1<<100
QUOTA = 50

r = remote("35.231.13.90", 5000)
#"arg1":{"op":"**", "arg1":2, "arg2":int(2**25)},
min = 0
max = MAX_NUM
for j in range(QUOTA):
    print(min, max, max-min)
    expr = {"op":"or",
             "arg1":{"op":"<", "arg1":"x", "arg2":(min + (max-min)//4)},
             "arg2":{"op":"and", 
                     "arg1":{"op":">=", "arg1":"x", "arg2":((min + 2*(max-min)//4))}, 
                     "arg2":{"op":"and", 
                             "arg1":{"op":"**", "arg1":2, "arg2":int(2**25)},
                             "arg2":{"op":"<", "arg1":"x", "arg2":((min + 3*(max-min)//4))}}}}
                             
    t1 = time.time()
    r.sendlineafter(b'Input your expression', str(expr))
    res = r.recvuntil(b'!')
    t2 = time.time()
    print(t2- t1, res)
    if b'Yes' in res:
        if t2-t1 < 0.3:
            max =  (min + (max-min)//4) - 1
            continue
        else:
            min, max = ((min + 2*(max-min)//4)), ((min + 3*(max-min)//4)) - 1
            continue
    else:
        if t2-t1 < 0.3:
            min, max = (min + (max-min)//4), (min + 2*(max-min)//4) - 1
            continue
        else:
            min = min + (3*(max-min)//4)
print(min, max, max-min)
r.sendline(str(min))
r.interactive()
    