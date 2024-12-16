import subprocess

EMAIL_BODY = "[TEST] Anamoly in Network detected"
SUBJECT = "[TEST] NETWORK ANAMOLY DETECTED"
RECIPIENT = "evan@evan-XPS-15-9520"

try:
    command = f'echo "{EMAIL_BODY}" | mail -s "{SUBJECT}" {RECIPIENT}'
    subprocess.run(command, shell=True, check=True)
    print("Email sent successfully!")
    
except subprocess.CalledProcessError as e:
    print(f"Failed to send email: {e}")