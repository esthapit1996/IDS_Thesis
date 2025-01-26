import subprocess
import syslog
from dotenv import load_dotenv
import os

load_dotenv()

SUBJECT = "NETWORK ANOMALY DETECTED"
RECIPIENT = os.getenv('RECIPIENT')

def send_alert(anomaly_type, anomaly_status):
    email_subject = f"[{anomaly_status}] {SUBJECT}"
    email_body = f"Anomaly in Network detected.\n\nAnomaly Details:\n{anomaly_type}"
    
    syslog.syslog(syslog.LOG_INFO, f"Attempting to send email alert for anomaly: {anomaly_type}")
    
    try:
        command = f'echo "{email_body}" | mail -s "{email_subject}" {RECIPIENT}'
        subprocess.run(command, shell=True, check=True)
        
        syslog.syslog(syslog.LOG_INFO, "Email sent successfully!")
        print("Email sent successfully!")
        
    except subprocess.CalledProcessError as e:
        syslog.syslog(syslog.LOG_ERR, f"Failed to send email: {e}")
        print(f"Failed to send email: {e}")