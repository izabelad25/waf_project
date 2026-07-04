import asyncio
from db.init_db import db

#BUFFER == temp storage
activity_logs_buffer = []
firewall_actions_buffer = []

#function for writing the batches to DUCKdb
def logs_writer():
    if not activity_logs_buffer and not firewall_actions_buffer:
        return
    
    #swap cu lista goala pt prevenire pierdere date 
    activity_batch = list(activity_logs_buffer)
    activity_logs_buffer.clear()
    actions_batch = list(firewall_actions_buffer)
    firewall_actions_buffer.clear()

    try:
        if activity_batch:
            db.executemany("INSERT INTO activity_logs " \
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)", activity_batch)
            
        if actions_batch:
            db.executemany("INSERT INTO firewall_actions " \
            "VALUES (?, ?, ?, ?, ?, ?)", actions_batch)
            
    except Exception as e:
        print(f"Error in writing log batches to DB: {e}")

#background function == runs the writer every second == avoids db crash
async def log_background_listener():
    while True:
        await asyncio.sleep(1)
        logs_writer()