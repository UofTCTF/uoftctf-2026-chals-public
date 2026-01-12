
import base64
import os
import requests
import time
try:
    import gmpy2
    HAVE_GMP = True
except ImportError:
    HAVE_GMP = False

VERSION = "s"
MODULUS = 2**1279 - 1


def python_sloth_root(x, diff, p):
    exponent = (p + 1) // 4
    for _ in range(diff):
        x = pow(x, exponent, p) ^ 1
    return x


def gmpy_sloth_root(x, diff, p):
    exponent = (p + 1) // 4
    for _ in range(diff):
        x = gmpy2.powmod(x, exponent, p).bit_flip(0)
    return int(x)


def sloth_root(x, diff, p):
    if HAVE_GMP:
        return gmpy_sloth_root(x, diff, p)
    return python_sloth_root(x, diff, p)


def encode_number(num):
    size = (num.bit_length() // 24) * 3 + 3
    return str(base64.b64encode(num.to_bytes(size, "big")), "utf-8")


def decode_number(enc):
    return int.from_bytes(base64.b64decode(bytes(enc, "utf-8")), "big")


def decode_challenge(enc):
    dec = enc.split(".")
    if dec[0] != VERSION:
        raise ValueError("unknown challenge version")
    return list(map(decode_number, dec[1:]))


def encode_challenge(arr):
    return ".".join([VERSION] + list(map(encode_number, arr)))


def solve_challenge(chal):
    start_ts = time.time()
    [diff, x] = decode_challenge(chal)
    y = sloth_root(x, diff, MODULUS)
    end_ts = time.time()
    print(f"Solved challenge in {end_ts - start_ts:.2f} seconds")
    return encode_challenge([y])


def get_pow_headers(base_url):
    r = requests.get(f"{base_url}/pow", timeout=15)
    r.raise_for_status()
    data = r.json()
    if not data.get("enabled"):
        return {}
    challenge = data["challenge"]
    token = data["token"]
    solution = solve_challenge(challenge)
    return {
        "X-PoW-Token": token,
        "X-PoW-Solution": solution,
    }

def main():
    base_url = os.environ.get("CHAL_URL", "http://127.0.0.1:5000")
    headers = get_pow_headers(base_url)
    with open("collision.zip", "rb") as f:
        r = requests.post(
            f"{base_url}/submit",
            files={"file": ("collision.zip", f, "application/zip")},
            headers=headers,
            timeout=60,
        )
    print("Response status:", r.status_code)
    print(r.json())


if __name__ == "__main__":
    main()
