import aiosmtplib 
from email.message import EmailMessage
import os
import sys
import json

from paths import app_dir
CONFIG_PATH = os.path.join(app_dir(), "waf_config.json")

from dotenv import load_dotenv
load_dotenv(dotenv_path=os.path.join(app_dir(), ".env"))

FROM = os.getenv("MAIL_ALERT") 
PASSWORD = os.getenv("MAIL_APP_PASS") #pass !! from env

def _get_recipient() -> str:
    #citeste email-ul setat de user din waf_config.json
    try:
        with open(CONFIG_PATH, 'r') as file:
            data = json.load(file)
            return data.get("alert_email", "").strip()
    except (FileNotFoundError, json.JSONDecodeError, OSError) as e:
        print(f"!ALERT! config file read err from {CONFIG_PATH}: {e}")
        return ""

async def sendMail(subject: str, text: str):
    email_notify = _get_recipient()

    if not email_notify:
        print("! No email configured -> email alert skipped")
        return
    if not FROM:
        print("! NO ENV EMAIL")
        return
    
    if not PASSWORD:
        print("! NO ENV PASSWORD ")
        return
    
    msg = EmailMessage()
    msg.set_content(text)
    msg['Subject'] = subject
    msg['From'] = FROM
    msg['To'] = email_notify
    
    try:
        #connect + secure conn to smtp server on port 587
        await aiosmtplib.send(
            msg,
            hostname='smtp.gmail.com',
            port=587,
            start_tls=True,
            username=FROM,
            password=PASSWORD
        )
        
        print("[ALERT] Email successfully sent!")
        
    except Exception as e:
        print(f"[ERROR] Failed to send email: {e}")
    