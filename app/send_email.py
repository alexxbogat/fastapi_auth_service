import aiosmtplib
from email.mime.text import MIMEText

from settings import EMAIL_HOST, EMAIL_PORT, EMAIL_USE_TLS, EMAIL_HOST_USER, EMAIL_HOST_PASSWORD


async def send_verification_email(to_email: str, token: str):
    """
    Send an account verification email to a user.

    Args:
        to_email (str): Recipient's email address.
        token (str): Verification token to be embedded in the URL.
    """
    verify_url = f'http://localhost:8000/verify?token={token}'
    msg = MIMEText(f'Click to verify your account: {verify_url}')
    msg['From'] = EMAIL_HOST_USER
    msg['To'] = to_email
    msg['Subject'] = 'Verify your account'

    await aiosmtplib.send(
        msg,
        hostname=EMAIL_HOST,
        port=int(EMAIL_PORT),
        start_tls=bool(EMAIL_USE_TLS),
        username=EMAIL_HOST_USER,
        password=EMAIL_HOST_PASSWORD
    )
