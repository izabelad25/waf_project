from fastapi import APIRouter
from db.init_db import db

waf_actions_router = APIRouter()

@waf_actions_router.get("/waf/actions")
async def get_firewall_actions(limit: int= 50, offset: int=0):
    #fetches every action the fw executed 
    #left join to combine action, rule name and blocked IP
    query = "SELECT" \
    " fa.action_id," \
    " fa.timestamp," \
    " fa.action_taken," \
    " fa.trigger," \
    " fa.rule_id," \
    " r.name AS rule_name," \
    " fa.activity_log_id," \
    " al.client_ip," \
    " al.request_path," \
    " FROM firewall_actions fa" \
    " LEFT JOIN rules r ON fa.rule_id = r.rule_id" \
    " LEFT JOIN activity_logs al ON fa.activity_log_id = al.log_id" \
    " ORDER BY fa.timestamp DESC" \
    " LIMIT ? OFFSET ?"

    rows = db.execute(query, (limit, offset)).fetchall()

    total = db.execute("SELECT COUNT (*) FROM firewall_actions").fetchone()[0]

    #data format --> FRONTEND
    waf_actions_list = []
    for row in rows:
        waf_actions_list.append({
            "action_id": row[0],
            "timestamp": row[1].isoformat() if row[1] else None,
            "action_taken": row[2],
            "trigger": row[3],
            "rule": {
                "id": row[4],
                "name": row[5] or "Blank"
            },
            "network":{
                "log_id": row[6],
                "client_ip": row[7] or "Unknown IP address",
                "request_path": row[8] or "Unknown Path"
            }
        })

    return {
        "data": waf_actions_list,
        "pagination": {
            "total_recs": total,
            "current_pg": (offset // limit) + 1,
            "total_pg": (total + limit - 1) // limit,
            "limit": limit
        }
    }

#route for getting a single action --> for detailed view in front
@waf_actions_router.get("/waf/actions/{action_id}")
async def get_action_by_id(action_id: str):
    query = "SELECT " \
    "fa.action_id, fa.timestamp, fa.action_taken, fa.trigger," \
    "r.name, al.client_ip, al.http_method, al.request_path, al.user_agent" \
    "FROM firewall_actions fa" \
    "LEFT JOIN rules r ON fa.rule_id = r.rule_id" \
    "LEFT JOIN activity_logs al ON fa.activity_log_id = al.log_id" \
    "WHERE fa.action_id = ?"

    row = db.execute(query, (action_id,)).fetchone()

    if not row:
        return {"error": "Action ID not found"}, 404
    
    return {
        "action_id": row[0],
        "timestamp": row[1].isoformat() if row[1] else None,
        "action_taken": row[2],
        "trigger": row[3],
        "rule_name": row[4],
        "client_ip": row[5],
        "http_method": row[6],
        "request_path": row[7],
        "user_agent": row[8]
    }