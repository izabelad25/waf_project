"""
populate_db.py
Populeaza fireball.db cu datele din test set (activity_logs_synthetic_final.csv)
Mapeaza coloanele CSV -> schema activity_logs din init_db.py:
  record_id  -> log_id
  timestamp  -> timestamp
  client_ip  -> client_ip
  field_a    -> http_method
  field_b    -> request_path
  field_c    -> status_code  (ALLOW=200, BLOCK=403)
  field_d    -> user_agent
  field_e    -> response_time_ms

Ruleaza din directorul server/:  python populate_db.py
"""

import os, sys, duckdb, pandas as pd

# ── Cai ──────────────────────────────────────────────────────────
_BASE    = os.path.dirname(os.path.abspath(__file__))
DB_PATH  = os.path.join(_BASE, "fireball.db")
CSV_PATH = os.path.join(_BASE, "log_analyzer", "activity_logs_synthetic_final.csv")

# ── Citire CSV ───────────────────────────────────────────────────
df = pd.read_csv(CSV_PATH)
test = df[df["dataset_split"] == "test"].copy().reset_index(drop=True)
print(f"Randuri test set: {len(test)}")

# ── Mapare status_code ───────────────────────────────────────────
def to_status(v):
    if str(v) == "BLOCK": return 403
    if str(v) == "ALLOW":  return 200
    try:   return int(float(v))
    except: return 200

test["status_code"]      = test["field_c"].apply(to_status)
test["response_time_ms"] = pd.to_numeric(test["field_e"], errors="coerce").fillna(0.0)
test["timestamp"]        = pd.to_datetime(test["timestamp"], errors="coerce")

# ── Inserare in DB ───────────────────────────────────────────────
conn = duckdb.connect(DB_PATH)

rows = [
    (
        str(r["record_id"]),
        r["timestamp"],
        str(r["client_ip"]),
        str(r["field_a"]),
        str(r["field_b"]),
        int(r["status_code"]),
        str(r["field_d"]),
        float(r["response_time_ms"]),
    )
    for _, r in test.iterrows()
]

conn.executemany(
    """
    INSERT OR IGNORE INTO activity_logs
    (log_id, timestamp, client_ip, http_method,
     request_path, status_code, user_agent, response_time_ms)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """,
    rows
)

total = conn.execute("SELECT COUNT(*) FROM activity_logs").fetchone()[0]
conn.close()

print(f"Inserate: {len(rows)} randuri")
print(f"Total in activity_logs: {total}")