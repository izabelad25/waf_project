"""
Fireball WAF - HTTP traffic simulator for the Isolation Forest scanner

Why this replays the training CSV instead of synthetic traffic
--------------------------------------------------------------
The IF model (isoForestModel.py) derives two of its strongest features,
url_freq and ua_freq, by mapping each live request's path / user-agent onto
the frequency maps learned FROM THE TRAINING SET. It also matches IOC tokens
in their *sanitized* form ("[<]script", "[union] [select]", ...), which is the
representation stored in activity_logs.

So for the scanner's detection to be coherent with how the model was trained:
  * normal traffic must reuse the paths / user-agents that are frequent in the
    training data  -> they map to high url_freq / ua_freq -> scored as normal
  * anomalies must be the rare paths / scanner user-agents / IOC-bearing
    requests from the dataset -> low freq + IOC -> scored as anomalies

The cleanest way to guarantee that is to replay rows from the very dataset the
model was trained/tested on, through the live proxy, with a realistic mix.

Run order:
    1. python main.py                 # WAF up on :8080
    2. python test_app.py             # backend so forwarded traffic gets 200
    3. python http_traffic_simulator.py
Then open the dashboard -> Anomaly Scanner -> Start scanning.
"""

import os
import time
import random
import re
import urllib.parse
import http.client

import pandas as pd

PROXY_HOST = "127.0.0.1"
PROXY_PORT = 8080
DELAY      = 0.05         # seconds between requests

# how many of each class to replay (mostly normal, a realistic slice anomalies)
N_NORMAL   = 400
N_ANOMALY  = 60

CSV_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "log_analyzer",
    "activity_logs_bun_diversified.csv",
)

VALID_METHODS = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}
METHODS_WITH_BODY = {"POST", "PUT", "PATCH"}

# fallback IP pool if the CSV has no usable client_ip
IP_POOL = [
    "203.0.113.10", "203.0.113.55", "198.51.100.7", "198.51.100.42",
    "192.0.2.13", "45.33.12.9", "185.220.101.3", "141.98.10.21",
]


_DEFANG_TOKEN = re.compile(r"\[([^\[\]]+)\]")


def undefang(value: str) -> str:
    """Inverse of the WAF's sanitize_* transforms.

    The CSV holds the POST-sanitize (archived) representation. To reproduce that
    exact form through the live pipeline we must send the PRE-sanitize (raw)
    value and let the proxy sanitize it exactly once. sanitize_* is NOT
    idempotent, so re-sending the already-sanitized value double-sanitizes:
        IP   "203[.]0[.]1"      -> sanitize_ip   -> "203[[.]]0[[.]]1"   (broken)
        path "[union] [select]" -> sanitize_path -> "[[union]] [[select]]" (broken)

    Both sanitizers wrap their tokens in [..]:  '.'->'[.]', '='->'[=]',
    'union'->'[union]', '<'->'[<]', etc. Stripping every [X] -> X reverses all
    of them in one pass. 'http'->'hxxp' is reversed separately.
    """
    s = str(value)
    s = _DEFANG_TOKEN.sub(r"\1", s)   # [.] -> .  [=] -> =  [union] -> union ...
    s = s.replace("hxxp", "http")     # reverse the http defang
    return s


def build_target(field_b: str) -> str:
    # De-fang the archived path back to its raw form, then encode for transport.
    # The proxy double-unquotes and sanitizes ONCE -> stored path == CSV field_b,
    # so url_freq / ua_freq / IOC matching line up with the training maps.
    path = undefang(field_b)
    if not path.startswith("/"):
        path = "/" + path
    return urllib.parse.quote(path, safe="/%?&=:+@!$'(),;~-._*")


def send(method, target, user_agent, ip):
    headers = {
        "User-Agent":      user_agent,
        "X-Forwarded-For": ip,     # proxy records this as the client IP
        "X-Real-IP":       ip,
        "Accept":          "*/*",
        "Connection":      "close",
    }
    body = None
    if method in METHODS_WITH_BODY:
        body = b""
        headers["Content-Length"] = "0"
    try:
        conn = http.client.HTTPConnection(PROXY_HOST, PROXY_PORT, timeout=5)
        conn.request(method, target, body=body, headers=headers)
        resp = conn.getresponse()
        resp.read()
        conn.close()
        return resp.status
    except Exception as e:
        return f"ERR({e})"


def pick_ip(row):
    ip = str(row.get("client_ip", "")).strip()
    if ip and ip.lower() != "nan":
        # CSV IP is sanitized (203[.]0[.]113[.]10). De-fang to raw so the proxy's
        # sanitize_ip re-applies exactly once -> stored IP matches the CSV form.
        return undefang(ip)
    return random.choice(IP_POOL)


def rows_for(df, want, label):
    if df.empty:
        print(f"  [warn] no {label} rows in dataset")
        return []
    take = df.sample(n=min(want, len(df)), random_state=random.randint(1, 9999))
    out = []
    for _, r in take.iterrows():
        method = str(r.get("field_a", "GET")).upper()
        if method not in VALID_METHODS:
            method = "GET"
        path = build_target(r.get("field_b", "/"))
        ua   = str(r.get("field_d", "Mozilla/5.0")) or "Mozilla/5.0"
        ip   = pick_ip(r)
        out.append((label, method, path, ua, ip))
    return out


def main():
    if not os.path.exists(CSV_PATH):
        print(f"CSV not found: {CSV_PATH}")
        return

    df = pd.read_csv(CSV_PATH)
    if "is_anomaly" not in df.columns:
        print("dataset has no 'is_anomaly' column - cannot split normal/anomaly")
        return

    normal_df  = df[df["is_anomaly"] == 0]
    anomaly_df = df[df["is_anomaly"] == 1]

    print("Fireball WAF - scanner traffic simulator (CSV replay)")
    print(f"Target  : http://{PROXY_HOST}:{PROXY_PORT}")
    print(f"Dataset : {os.path.basename(CSV_PATH)}  "
          f"(normal={len(normal_df)}, anomaly={len(anomaly_df)})")
    print(f"Sending : {N_NORMAL} normal + {N_ANOMALY} anomaly")
    print("-" * 64)

    batch = rows_for(normal_df, N_NORMAL, "normal") + \
            rows_for(anomaly_df, N_ANOMALY, "anomaly")
    random.shuffle(batch)

    ok = blocked = other = 0
    total = len(batch)
    for i, (label, method, target, ua, ip) in enumerate(batch, 1):
        status = send(method, target, ua, ip)
        if status == 403:
            blocked += 1; marker = "[BLOCK]"
        elif isinstance(status, int) and status < 400:
            ok += 1; marker = "[OK]   "
        else:
            other += 1; marker = "[--]   "

        if i % 20 == 0 or i == total:
            print(f"  {marker} {i:4d}/{total}  {label:7s}  {ip:15s}  "
                  f"{method:4s}  {str(status):3}  {urllib.parse.unquote(target)[:46]}")
        time.sleep(DELAY)

    print("-" * 64)
    print(f"Done:  OK={ok}  BLOCK={blocked}  OTHER={other}  TOTAL={total}")
    print("Now open the dashboard -> Anomaly Scanner -> Start scanning.")
    print("Normal rows reuse frequent dataset paths/UAs (-> high url_freq/ua_freq),")
    print("anomaly rows carry rare paths / scanner UAs / IOC tokens (-> flagged).")


if __name__ == "__main__":
    main()