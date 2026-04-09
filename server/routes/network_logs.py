from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from db.init_db import db

logs_router = APIRouter()

#logs need to be immuable READ ONLY

#READ
@logs_router.get("/waf/network_logs")
async def get_logs(limit: int = 100, offset: int = 0):
    rows = db.execute("SELECT * FROM activity_logs ORDER BY timestamp DESC LIMIT ? OFFSET ?", (limit, offset)).fetchall()

    logs_list = []
    for row in rows:
        logs_list.append({
            "log_id": row[0],
            "timestamp": row[1].isoformat() if row[1] else None, 
            "client_ip": row[2],
            "http_method": row[3],
            "request_path": row[4],
            "status_code": row[5],
            "user_agent": row[6],
            "response_time_ms": row[7]
        })
    return {"logs": logs_list}

#ROUTE FOR ANALYTICS ! (trb modificata mai tarziu)
@logs_router.get("/waf/analytics")
async def get_log_stats():
    
    total_reqs = db.execute("SELECT COUNT(*) FROM activity_logs").fetchone()[0]
    #fetch total reqs by req code
        #trebuie refactored ca o functie sau ceva ca sa poti introduce codul ++ 
        # ++ cateva standard ex: blocked reqs
    blocked_requests = db.execute("SELECT COUNT(*) FROM activity_logs WHERE status_code = 403").fetchone()[0]
    
    #top 3 cele mai active adrese ip 
    top_ips = db.execute(
        "SELECT client_ip, COUNT(*) as topIPs " \
        " FROM activity_logs " \
        " GROUP BY client_ip " \
        " ORDER BY topIPs DESC " \
        " LIMIT 3"
    ).fetchall()

    return{
        "total_requests": total_reqs,
        "blocked_requests": blocked_requests,
        #trb completat cu requests in functie de cod
        "top_ips": [{"ip": row[0], "topIPs": row[1]} for row in top_ips] 
    }



