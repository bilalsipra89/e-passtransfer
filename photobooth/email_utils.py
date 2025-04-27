import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from django.conf import settings

def send_email(recipient_email, subject, body):
    """
    Send an email using SMTP with SSL.
    
    Args:
        recipient_email (str): The recipient's email address
        subject (str): Email subject line
        body (str): Email body content (can be HTML)
        
    Returns:
        bool: True if email was sent successfully, False otherwise
    """
    # Email credentials from settings
    sender_email = settings.EMAIL_HOST_USER
    password = settings.EMAIL_HOST_PASSWORD
    smtp_server = settings.EMAIL_HOST
    smtp_port = settings.EMAIL_PORT

    # Create message
    message = MIMEMultipart()
    message["From"] = sender_email
    message["To"] = recipient_email
    message["Subject"] = subject

    # Add body to email
    message.attach(MIMEText(body, "html"))

    # Initialize server variable
    server = None
    
    try:
        # Create SMTP SSL session
        server = smtplib.SMTP_SSL(smtp_server, smtp_port)
        server.login(sender_email, password)

        # Send email
        text = message.as_string()
        server.sendmail(sender_email, recipient_email, text)
        return True

    except Exception as e:
        print(f"DEBUG: Email sending error: {str(e)}")
        return False

    finally:
        if server:
            server.quit() 