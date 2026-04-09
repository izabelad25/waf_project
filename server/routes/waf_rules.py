from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from db.init_db import db, CACHE_IPS, CACHE_REGEX, reload_cache


rule_router = APIRouter()

#using base models for automatic validation + type casting 

class RuleCreate(BaseModel):
    name: str
    rule_type: str       # 'IP_MATCH' sau 'REGEX_MATCH'
    target_zone: str     # 'CLIENT_IP', 'PATH', 'HEADERS', 'QUERY_STRING', 'BODY'
    match_pattern: str
    action: str = "BLOCK" #default action

class RuleUpdate(BaseModel):
    name: str | None = None
    action: str | None = None
    is_active: bool | None = None


#READ all rules
@rule_router.get("/waf/rules")
async def get_all_rules():
    rows = db.execute("SELECT * FROM rules").fetchall()

    rules_list = []
    for row in rows:
        rules_list.append({
            "id": row[0], 
            "name": row[1],
            "rule_type": row[2],
            "target_zone": row[3],
            "match_pattern": row[4],
            "action": row[5],
            "is_active": row[6]
        })
    return {"rules": rules_list}

#CREATE new rule
@rule_router.post("/waf/rules")
async def create_rule(rule: RuleCreate):
    #autoincrement pt next id
    next_id = db.execute("SELECT COALESCE(MAX(rule_id), 0) + 1 FROM rules").fetchone()[0]

    db.execute("INSERT INTO rules (rule_id, name, rule_type, target_zone, match_pattern, action, is_active)" \
    "VALUES (?, ?, ?, ?, ?, ?, ?)", (next_id, rule.name, rule.rule_type, rule.target_zone, rule.match_pattern, rule.action, True))

    reload_cache()
    return {"status": "success", "message": f"Rule '{rule.name}' created", "id": next_id}

#UPDATE rule
@rule_router.put("/waf/rules/{rule_id}")
async def update_rule(rule_id: int, updates: RuleUpdate):
    exists = db.execute("SELECT 1 FROM rules WHERE rule_id = ?", (rule_id,)).fetchone()

    if not exists:
        raise HTTPException(status_code=404, detail="Rule not found")
    
    if updates.name is not None:
        db.execute("UPDATE rules SET name = ? WHERE rule_id = ?", (updates.name, rule_id))
    if updates.action is not None:
        db.execute("UPDATE rules SET action =? WHERE rule_id = ?", (updates.action, rule_id))
    if updates.is_active is not None:
        db.execute("UPDATE rules SET is_active =? WHERE rule_id = ?", (updates.is_active, rule_id))
    
    db.execute("UPDATE rules SET updated_at = CURRENT_TIMESTAMP WHERE rule_id = ?", (rule_id,))

    reload_cache()
    return {"status": "success", "message": f"Rule {rule_id} updated"}

#DELETE
@rule_router.delete("/waf/rules/{rule_id}")
async def delete_rule(rule_id: int):
    db.execute("DELETE FROM rules WHERE rule_id = ?", (rule_id,))
    reload_cache()

    return {"status": "success", "message": f"Rule {rule_id} deleted"}

