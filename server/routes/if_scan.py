from fastapi import APIRouter
from fastapi.responses import JSONResponse
from db.init_db import db, CACHE_IPS
from db.logger import firewall_actions_buffer
from db.init_db import add_new_rule
from datetime import datetime
import uuid
import asyncio
from db.sanitize_data import sanitize_ip, sanitize_path
 
if_scan_router = APIRouter()
 
 
@if_scan_router.post("/waf/if_scan")
async def run_if_scan():
    
    try:
        from log_analyzer.if_scanner import run_scan
        result = run_scan(db)
        return JSONResponse(result)
    except Exception as e:
        import traceback
        tb = traceback.format_exc()
        print(f"[IF SCAN ERROR]\n{tb}")
        return JSONResponse({"error": str(e), "traceback": tb}, status_code=500)
 
 
@if_scan_router.post("/waf/if_scan/block/{client_ip:path}")
async def block_ip_from_scan(client_ip: str):
   
    try:
        if client_ip in CACHE_IPS:
            return JSONResponse({"status": "already_blocked", "ip": client_ip})
 
        CACHE_IPS.add(client_ip)
        current_time = datetime.now()
        trigger      = "if_anomaly_scan"
        reason       = f"Blocked by IF anomaly scanner"
 
        new_rule_id = add_new_rule(
            f"Scanner block {client_ip}",
            "IP_MATCH", "IP", client_ip, action="BLOCK"
        )
 
        
        firewall_actions_buffer.append((
            str(uuid.uuid4()), current_time, None,
            new_rule_id, "BLOCK", sanitize_path(reason)
        ))
 
        return JSONResponse({
            "status":  "blocked",
            "ip":      sanitize_ip(client_ip),
            "rule_id": new_rule_id,
        })
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)
    
@if_scan_router.post("/waf/retrain")
async def retrain_model():
    """
    Retrains the Isolation Forest model using archived Parquet files.
    Runs in a thread executor (CPU-bound) — does not block the event loop.
    The new model is hot-swapped into if_scanner globals immediately,
    so the next /waf/if_scan call uses the retrained model without restart.
    """
    try:
        from db.archiver_db import ARCHIVE_DIR
        from log_analyzer.if_scanner import retrain
 
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, retrain, ARCHIVE_DIR)
 
        if "error" in result:
            messages = {
                "no_archives":     "No archive files found. The archiver runs automatically when DB exceeds 200 MB.",
                "no_data":         "Archive files contain no activity_log rows.",
                "not_enough_data": f"Need at least 100 rows, found {result.get('count', 0)}.",
            }
            return JSONResponse(
                {"error": result["error"],
                 "message": messages.get(result["error"], "Unknown error")},
                status_code=400
            )
 
        return JSONResponse(result)
 
    except Exception as e:
        import traceback
        return JSONResponse(
            {"error": str(e), "traceback": traceback.format_exc()},
            status_code=500
        )
 