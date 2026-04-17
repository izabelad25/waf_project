"""
db/log_bridge.py
================
Proxy process  →  UDP :19567  →  Dashboard process  →  DuckDB

Why UDP:
  - Fire-and-forget: proxy never blocks waiting for a response
  - Zero chance of deadlocking the async event loop
  - No TCP handshake overhead per log entry
  - If dashboard is briefly busy, packets are dropped (acceptable for logs)

Protocol: newline-terminated JSON, max ~4KB per packet (well under UDP 64KB limit).
"""

import asyncio
import json
import socket
import logging
from datetime import datetime

log = logging.getLogger("WAF.Bridge")

LOG_HOST = "127.0.0.1"
LOG_PORT = 19567          # internal only, never exposed

# ── PROXY SIDE: send ──────────────────────────────────────────────────────────

_udp_sock: socket.socket | None = None

def _get_sock() -> socket.socket:
    global _udp_sock
    if _udp_sock is None:
        _udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return _udp_sock


def _send(payload: dict):
    """Synchronous UDP send — called from threadpool so it never blocks async loop."""
    try:
        data = json.dumps(payload, default=str).encode("utf-8")
        _get_sock().sendto(data, (LOG_HOST, LOG_PORT))
    except Exception as e:
        log.debug(f"UDP send failed: {e}")


async def send_activity(
    request_id: str,
    timestamp: datetime,
    client_ip: str,
    method: str,
    path: str,
    status_code: int,
    user_agent: str,
    response_time_ms: float,
):
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, _send, {
        "type":             "activity",
        "log_id":           request_id,
        "timestamp":        timestamp.isoformat(),
        "client_ip":        client_ip,
        "http_method":      method,
        "request_path":     path,
        "status_code":      status_code,
        "user_agent":       user_agent,
        "response_time_ms": response_time_ms,
    })


async def send_action(
    timestamp: datetime,
    request_id: str,
    rule_id: int,
    action: str,
    trigger: str,
):
    import uuid
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, _send, {
        "type":         "action",
        "action_id":    str(uuid.uuid4()),
        "timestamp":    timestamp.isoformat(),
        "log_id":       request_id,
        "rule_id":      rule_id,
        "action_taken": action,
        "trigger":      trigger,
    })


# ── DASHBOARD SIDE: receive + write to DuckDB ─────────────────────────────────

async def start_log_receiver():
    """
    Runs inside the dashboard process.
    Listens on UDP :19567, batches incoming packets, writes to DuckDB every second.
    DuckDB is only ever written from this single coroutine — no concurrency issues.
    """
    from db.init_db import db

    loop = asyncio.get_event_loop()

    # bind UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((LOG_HOST, LOG_PORT))
    sock.setblocking(False)

    log.info(f"Log receiver listening on UDP {LOG_HOST}:{LOG_PORT}")

    activity_batch = []
    action_batch   = []

    async def flush():
        nonlocal activity_batch, action_batch
        if activity_batch:
            try:
                db.executemany(
                    "INSERT OR IGNORE INTO activity_logs VALUES (?,?,?,?,?,?,?,?)",
                    activity_batch
                )
            except Exception as e:
                log.error(f"DB activity write error: {e}")
            activity_batch = []

        if action_batch:
            try:
                db.executemany(
                    "INSERT OR IGNORE INTO firewall_actions VALUES (?,?,?,?,?,?)",
                    action_batch
                )
            except Exception as e:
                log.error(f"DB action write error: {e}")
            action_batch = []

    last_flush = loop.time()

    while True:
        # drain all waiting UDP packets without blocking
        try:
            while True:
                data, _ = sock.recvfrom(65535)
                try:
                    pkt = json.loads(data.decode("utf-8"))
                except Exception:
                    continue

                if pkt.get("type") == "activity":
                    activity_batch.append((
                        pkt["log_id"],
                        pkt["timestamp"],
                        pkt["client_ip"],
                        pkt["http_method"],
                        pkt["request_path"],
                        pkt["status_code"],
                        pkt["user_agent"],
                        pkt["response_time_ms"],
                    ))
                elif pkt.get("type") == "action":
                    action_batch.append((
                        pkt["action_id"],
                        pkt["timestamp"],
                        pkt["log_id"],
                        pkt["rule_id"],
                        pkt["action_taken"],
                        pkt["trigger"],
                    ))
        except BlockingIOError:
            pass  # no more packets right now

        # flush to DB once per second
        now = loop.time()
        if now - last_flush >= 1.0:
            await flush()
            last_flush = now

        await asyncio.sleep(0.05)   # 50ms poll — low CPU, fast enough for live UI