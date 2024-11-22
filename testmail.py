import smtplib
from email.mime.text import MIMEText

sender_email = 'aquadetect001@gmail.com'
receiver_email = 'dion.alimoren@gmail.com'
password = 'mkaa yluz sqqa pvgk'

msg = MIMEText('This is a test email.')
msg['Subject'] = 'Test Email'
msg['From'] = sender_email
msg['To'] = receiver_email

try:
    with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
        server.login(sender_email, password)
        server.sendmail(sender_email, receiver_email, msg.as_string())
    print("Email sent successfully!")
except Exception as e:
    print(f"Error: {e}")
