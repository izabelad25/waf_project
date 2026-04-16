import json
import os
import httpx

from fastapi import APIRouter
from fastapi.responses import JSONResponse
from pydantic import BaseModel

config_router = APIRouter()


#preparing for packaging to exe file
_BASE = getattr(__import__('sys'), '_MEIPASS', os.path.dirname(os.path.abspath(__file__)))
CONFIG_PATH = os.path.join(os.path.dirname(_BASE), "waf_config.json")

_DEFAULTS = {
    "target_host": "127.0.0.1",
    "target_port": 3000,
    "alert_email": "",
}

#loading config file
def load_config() -> dict:
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH) as f:
                data = json.load(f)
                return {**_DEFAULTS, **data}
        except Exception:
            pass
    return dict(_DEFAULTS)

#save config file
def save_config(cfg: dict):
    with open(CONFIG_PATH, "w") as f:
        json.dump(cfg, f, indent=2)

#proxy state and configuration
PROXY_STATE: dict = {}

def _build_client(host: str, port: int) -> httpx.AsyncClient:
    url = f"http://{host}:{port}"
    return httpx.AsyncClient(base_url=url, timeout=15.0)
 
 
def init_proxy_state():
    cfg = load_config()
    PROXY_STATE["config"] = cfg
    PROXY_STATE["client"] = _build_client(cfg["target_host"], cfg["target_port"])

#configuration model for payloads
class ConfigPayload(BaseModel):
    target_host: str
    target_port: int
    alert_email: str = ""

#routes

@config_router.get("/waf/config")
async def get_config():
    cfg = PROXY_STATE.get("config", load_config())
    return JSONResponse(cfg)
 
 
@config_router.post("/waf/config")
async def set_config(payload: ConfigPayload):
    cfg = {
        "target_host": payload.target_host.strip(),
        "target_port": payload.target_port,
        "alert_email": payload.alert_email.strip(),
    }
 
    old_client = PROXY_STATE.get("client")
    PROXY_STATE["config"] = cfg
    PROXY_STATE["client"] = _build_client(cfg["target_host"], cfg["target_port"])
 
    # close old client in background
    if old_client:
        try:
            await old_client.aclose()
        except Exception:
            pass
 
    save_config(cfg)
 
    return JSONResponse({"ok": True, "target": f"http://{cfg['target_host']}:{cfg['target_port']}"})


@config_router.get("/waf/config/reachable")
async def check_reachable():
    """ TCP probe — called by the UI to update the status bar. god help me"""
    cfg = PROXY_STATE.get("config", load_config())
    import asyncio, socket
 
    host = cfg["target_host"]
    port = cfg["target_port"]
 
    loop = asyncio.get_event_loop()
    try:
        await asyncio.wait_for(
            loop.run_in_executor(None, lambda: _tcp_probe(host, port)),
            timeout=1.5,
        )
        return JSONResponse({"reachable": True, "target": f"{host}:{port}"})
    except Exception:
        return JSONResponse({"reachable": False, "target": f"{host}:{port}"})

def _tcp_probe(host: str, port: int):
    import socket
    s = socket.socket()
    s.settimeout(1.0)
    s.connect((host, port))
    s.close()