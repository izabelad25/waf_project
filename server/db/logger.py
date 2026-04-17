#pastrat ca sa nu refac tot proxy ul

from db.log_bridge import send_activity as log_activity
from db.log_bridge import send_action   as log_action

# backward-compat stubs (nothing appends to these anymore)
activity_logs_buffer   = []
firewall_actions_buffer = []

async def log_background_listener():
    """No-op — receiver runs via start_log_receiver() in main.py startup."""
    import asyncio
    while True:
        await asyncio.sleep(60)