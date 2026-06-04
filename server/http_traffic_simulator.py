"""
Fireball WAF - HTTP traffic simulator (realistic)

Sends REAL HTTP requests through the WAF proxy (:8080) so that the firewall
engine itself evaluates each request and records proper firewall_actions
(real rule_id -> rule name + the matched trigger). This is what makes the
Actions view show clearly WHICH rule blocked and WHY, unlike direct DB
population.

Different source IPs are spoofed via the X-Forwarded-For header. For these to
show up in Actions, the proxy must honor that header (see reverse_proxy.py).

Run order:
    1. python main.py                 # WAF up on :8080
    2. python test_app.py             # optional backend so benign traffic gets 200
    3. python http_traffic_simulator.py
"""

import time
import random
import http.client

PROXY_HOST = "127.0.0.1"
PROXY_PORT = 8080
DELAY      = 0.15          # seconds between requests
ROUNDS     = 60           # how many requests to send

# pool of fake client IPs -> sent via X-Forwarded-For
CLIENT_IPS = [
    "203.0.113.10", "203.0.113.55", "198.51.100.7", "198.51.100.42",
    "192.0.2.13", "192.0.2.200", "45.33.12.9", "185.220.101.3",
    "8.8.8.8", "141.98.10.21",
]

# Each entry: (label, method, path, body, extra_headers)
# Paths/payloads chosen to trigger the default rules in init_db.py.

BENIGN = [
    ("benign", "GET",  "/",                         None, {}),
    ("benign", "GET",  "/index.html",               None, {}),
    ("benign", "GET",  "/api/products?id=42",       None, {}),
    ("benign", "GET",  "/about",                    None, {}),
    ("benign", "POST", "/api/login",                b"user=alice&pass=secret", {}),
    ("benign", "GET",  "/static/app.css",           None, {}),
    ("benign", "GET",  "/search?q=laptop",          None, {}),
]

ATTACKS = [
    # --- SQL injection ---
    ("SQLi UNION SELECT",  "GET",
        "/api/products?id=1 UNION SELECT username,password FROM users", None, {}),
    ("SQLi auth bypass",   "GET",
        "/login?user=admin'--%20-&pass=x", None, {}),
    ("SQLi auth bypass",   "GET",
        "/login?user=admin' OR '1'='1", None, {}),
    ("SQLi in body",       "POST",
        "/api/login", b"username=admin'-- -&password=x", {}),

    # --- XSS ---
    ("XSS script tag",     "GET",
        "/search?q=<script>alert(1)</script>", None, {}),
    ("XSS event handler",  "GET",
        "/page?name=<img src=x onerror=alert(1)>", None, {}),
    ("XSS javascript URI", "GET",
        "/redirect?u=javascript:alert(document.cookie)", None, {}),
    ("XSS in body",        "POST",
        "/comment", b"text=<script>steal()</script>", {}),

    # --- Path traversal (double-encoded -> normalised by proxy) ---
    ("Path traversal",     "GET",
        "/static/%252e%252e%252fetc/passwd", None, {}),
    ("Sensitive file",     "GET",
        "/var/www/etc/passwd", None, {}),

    # --- Command injection ---
    ("Command injection",  "GET",
        "/ping?host=;whoami", None, {}),
    ("Command injection",  "POST",
        "/exec", b"cmd=;cat /etc/shadow", {}),

    # --- Header-based ---
    ("SQLi in header",     "GET",
        "/", None, {"X-Forwarded-Host": "' OR '1'='1"}),
    ("XSS in header",      "GET",
        "/", None, {"X-Custom": "<script>alert(1)</script>"}),
]

METHODS_WITH_BODY = {"POST", "PUT", "PATCH"}


def send(ip, label, method, path, body, extra_headers):
    headers = {
        "User-Agent":      "FireballSim/1.0",
        "X-Forwarded-For": ip,     # proxy reads this as the client IP
        "X-Real-IP":       ip,
        "Accept":          "*/*",
        "Connection":      "close",
    }
    headers.update(extra_headers)
    if method in METHODS_WITH_BODY:
        body = body or b""
        headers["Content-Length"] = str(len(body))
        headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
    else:
        body = None

    try:
        conn = http.client.HTTPConnection(PROXY_HOST, PROXY_PORT, timeout=5)
        conn.request(method, path, body=body, headers=headers)
        resp = conn.getresponse()
        resp.read()
        conn.close()
        return resp.status
    except Exception as e:
        return f"ERR({e})"


def main():
    print("Fireball WAF - HTTP traffic simulator (realistic)")
    print(f"Target : http://{PROXY_HOST}:{PROXY_PORT}")
    print(f"Rounds : {ROUNDS}   Delay : {DELAY}s")
    print("-" * 60)

    ok = blocked = other = 0

    # weighted mix: ~55% attacks so Actions fills up clearly, rest benign
    for i in range(1, ROUNDS + 1):
        ip = random.choice(CLIENT_IPS)
        if random.random() < 0.55:
            label, method, path, body, hdr = random.choice(ATTACKS)
        else:
            label, method, path, body, hdr = random.choice(BENIGN)

        status = send(ip, label, method, path, body, hdr)

        if status == 403:
            blocked += 1; marker = "[BLOCK]"
        elif isinstance(status, int) and status < 400:
            ok += 1; marker = "[OK]   "
        else:
            other += 1; marker = "[--]   "

        print(f"  {marker} {i:3d}/{ROUNDS}  {ip:15s}  {method:4s}  {str(status):3}  "
              f"{label:18s}  {path[:42]}")
        time.sleep(DELAY)

    print("-" * 60)
    print(f"Done:  OK={ok}  BLOCK={blocked}  OTHER={other}  TOTAL={ROUNDS}")
    print("Open the dashboard -> Actions to see rule name + trigger per block.")


if __name__ == "__main__":
    main()