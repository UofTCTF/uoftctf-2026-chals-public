import os
import subprocess
import tempfile
import requests

GPT_URL = "https://gpt2-service-77505077720.us-central1.run.app"

def extract_c_code(text):
    inside = False
    out = []
    for line in text.splitlines():
        s = line.strip()
        if not inside:
            if s.startswith("```") and s[3:].strip().lower() == "c":
                inside = True
            continue
        else:
            if s == "```":
                return "\n".join(out)
            out.append(line)
    return None


if __name__ == "__main__":
    # Proof of Work
    if os.system("python3 /app/pow.py ask 31337") != 0:
        exit(1)
        
    prompt = input("User: ")
    if "\n" in prompt or "\r" in prompt:
        print("Prompt should be one line.")
        exit(1)
    if "User:" in prompt or "Assistant:" in prompt:
        print("What are you trying to do???")
        exit(1)

    msg = "User: {}\nAssistant: ".format(prompt)
    output = requests.post(f"{GPT_URL}/predict", data=msg.encode("utf-8"), timeout=300).text

    print("Assistant: {}".format(output))

    c_code = extract_c_code(output)
    if c_code is None:
        print("Missing C code")
        exit(1)

    for blacklist_word in ["system", "exec", "open"]:
        if blacklist_word in c_code.lower():
            print("Blacklisted keyword detected.")
            exit(1)
    print("C Program detected:\n```C\n{}\n```".format(c_code))
    with tempfile.NamedTemporaryFile(suffix=".c", mode="w", dir="/ctf", delete=True) as f:
        f.write(c_code)
        f.seek(0)
    
        jail_cmd = f"/src/nsjail/nsjail -Mo --chroot / -T /tmp --skip_setsid --quiet -- /bin/sh /app/run_vibe_code.sh {f.name}"
        os.system(jail_cmd)