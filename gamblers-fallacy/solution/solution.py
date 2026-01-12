from datetime import datetime
import hashlib
import hmac
from randcrack import RandCrack
import pwn
import time

def roll_dice(clientseed : str, nonce : int) -> int:
    server_seed = rc.predict_randrange(0, 4294967295)
    nonce_client_msg = f"{clientseed}-{nonce}".encode()
    sig = hmac.new(str(server_seed).encode(), nonce_client_msg, hashlib.sha256).hexdigest()
    index = 0
    lucky = int(sig[index*5:index*5+5], 16)
    while (lucky >= 1e6):
        index += 1;
        lucky = int(sig[index * 5:index * 5 + 5], 16);
        if (index * 5 + 5 > 129):
            lucky = 9999;
            break;
    return round((lucky % 1e4) * 1e-2);

conn = pwn.remote('localhost',5000)

conn.recvuntil(b'> ')
conn.sendline(b'b')
conn.recvuntil(b': ')
conn.sendline(b'1')
conn.recvuntil(b': ')
conn.sendline(b'624')
conn.recvuntil(b': ')
conn.sendline(b'98')
conn.recvuntil(b'? ')
conn.sendline(b'Y')

# Receive the next line(s) of output
response = conn.recvuntil(b'> ')  # if it returns to menu
response_decoded = response.decode('utf-8').split('\n')
rc = RandCrack()

results_list = []
for i in range(624):
    results_list.append(int(response_decoded[i].split()[-1]))
#results = open("results.txt", 'r').read().split('\n')
#for line in results:
#    try:
#        results_list.append(line.split()[-1])
#    except:
#        pass

for i in range(624):
    exp = int(results_list[i])
    rc.submit(exp)

known_balance = 0
nonce = 624
while True:
    print("======")
    print(known_balance)
    print("======")
    if known_balance >= 10000:
        print(known_balance)
        conn.sendline(b'a')
        print(conn.recvuntil(b'a) '))
        conn.sendline(b'a')
        print(conn.recvuntil(b': '))
        print(conn.recvall(timeout=2))
        break;
    else:
        time.sleep(0.1)
        known_balance = float(response_decoded[-7].split()[-1])
        conn.sendline(b'b')
        print(conn.recvuntil(b': '))
        conn.sendline(f'{round(known_balance-1)}'.encode())
        #conn.sendline(round(known_balance-1).to_bytes())
        print(conn.recvuntil(b': '))
        conn.sendline(b'1')
        print(conn.recvuntil(b': '))
        conn.sendline(f'{roll_dice("1337awesome", nonce)}'.encode())
        #conn.sendline(roll_dice("1337awesome", nonce).to_bytes())
        print(conn.recvuntil(b'? '))
        conn.sendline(b'Y')
        response_decoded = (conn.recvuntil(b'> ')).decode('utf-8').split('\n')
        print(response_decoded)
        nonce+=1
