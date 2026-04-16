import aiosmtplib 
from email.message import EmailMessage

FROM = 'firewallapplicenta@gmail.com'
TO = 'dumitru.izzabela@gmail.com'

#pass !! atentie sa nu lasi asta aici
PASSWORD = ""

async def sendMail(subject: str, text: str):
    
    msg = EmailMessage()
    msg.set_content(text)
    msg['Subject'] = subject
    msg['From'] = FROM
    msg['To'] = TO
    
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
    