import uvicorn
import asyncio
from fastapi import FastAPI

from db import init_db
from db.logger import log_background_listener

from routes.waf_rules import rule_router 
from routes.network_logs import logs_router
from routes.waf_actions_log import waf_actions_router
from routes.reverse_proxy import proxy_router

from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from fastapi.middleware.cors import CORSMiddleware



app = FastAPI(title="Fireball")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

app.include_router(rule_router)
app.include_router(logs_router)
app.include_router(waf_actions_router)

#interface
app.mount("/client", StaticFiles(directory="client"), name="client")
@app.get("/")
async def dashboard():
    return FileResponse("client/dashboard.html")



#ruta proxy ULTIMA MEREU
app.include_router(proxy_router)

#background listener for collecting logs into batches
@app.on_event("startup")
async def startup_listener():
    #infinite loop since startup
    asyncio.create_task(log_background_listener())
    

if __name__ == "__main__":
    print("Firewall active ! :)")
    uvicorn.run("main:app", host="127.0.0.1", port=8000)

