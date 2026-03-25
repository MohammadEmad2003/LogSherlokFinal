"""
Email Service
Sends OTP and notification emails
"""
import os
import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Optional
import logging

logger = logging.getLogger(__name__)

# Email Configuration
SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
FROM_EMAIL = os.getenv("FROM_EMAIL", "noreply@forensic-agent.local")
FROM_NAME = os.getenv("FROM_NAME", "Forensic Agent")


class EmailService:
    """Email service for sending OTP and notifications."""

    def __init__(self):
        self.host = SMTP_HOST
        self.port = SMTP_PORT
        self.user = SMTP_USER
        self.password = SMTP_PASSWORD
        self.from_email = FROM_EMAIL
        self.from_name = FROM_NAME
        self._is_configured = bool(self.user and self.password)

    def is_configured(self) -> bool:
        """Check if email service is properly configured."""
        return self._is_configured

    def send_email(
        self,
        to_email: str,
        subject: str,
        html_content: str,
        text_content: Optional[str] = None
    ) -> bool:
        """Send an email."""
        if not self._is_configured:
            logger.warning(f"Email service not configured. Would send to {to_email}: {subject}")
            # Log OTP for development/testing when email is not configured
            if "OTP" in subject or "Password Reset" in subject:
                logger.info(f"[DEV MODE] Email to {to_email} - Subject: {subject}")
                logger.info(f"[DEV MODE] Content preview: {text_content[:200] if text_content else html_content[:200]}")
            return True  # Return True in dev mode so flow continues

        try:
            message = MIMEMultipart("alternative")
            message["Subject"] = subject
            message["From"] = f"{self.from_name} <{self.from_email}>"
            message["To"] = to_email

            # Plain text version
            if text_content:
                part1 = MIMEText(text_content, "plain")
                message.attach(part1)

            # HTML version
            part2 = MIMEText(html_content, "html")
            message.attach(part2)

            # Create secure connection
            context = ssl.create_default_context()

            with smtplib.SMTP(self.host, self.port) as server:
                server.starttls(context=context)
                server.login(self.user, self.password)
                server.sendmail(self.from_email, to_email, message.as_string())

            logger.info(f"Email sent successfully to {to_email}")
            return True

        except Exception as e:
            logger.error(f"Failed to send email to {to_email}: {str(e)}")
            return False

    def send_otp_email(self, to_email: str, otp: str, purpose: str = "password reset") -> bool:
        """Send OTP email for password reset or verification."""
        subject = f"Your Forensic Agent {purpose.title()} Code"

        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{ font-family: 'Segoe UI', Arial, sans-serif; background-color: #0a0f1a; color: #e0e0e0; }}
                .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                .header {{ background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }}
                .header h1 {{ color: #00ff88; margin: 0; font-size: 28px; }}
                .content {{ background: #1a1a2e; padding: 30px; border-radius: 0 0 10px 10px; }}
                .otp-box {{ background: linear-gradient(135deg, #0f3460 0%, #1a1a2e 100%); padding: 20px; text-align: center; border-radius: 10px; margin: 20px 0; border: 2px solid #00ff88; }}
                .otp-code {{ font-size: 36px; font-weight: bold; color: #00ff88; letter-spacing: 8px; font-family: 'Courier New', monospace; }}
                .warning {{ color: #ff6b6b; font-size: 14px; margin-top: 20px; }}
                .footer {{ text-align: center; margin-top: 20px; color: #666; font-size: 12px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🔐 Forensic Agent</h1>
                </div>
                <div class="content">
                    <p>Hello,</p>
                    <p>You requested a {purpose} for your Forensic Agent account. Use the following 6-digit code to proceed:</p>

                    <div class="otp-box">
                        <div class="otp-code">{otp}</div>
                    </div>

                    <p>This code will expire in <strong>10 minutes</strong>.</p>

                    <p class="warning">⚠️ If you didn't request this code, please ignore this email and ensure your account is secure.</p>
                </div>
                <div class="footer">
                    <p>Autonomous Forensic Investigation Agent</p>
                    <p>This is an automated message. Please do not reply.</p>
                </div>
            </div>
        </body>
        </html>
        """

        text_content = f"""
        Forensic Agent - {purpose.title()} Code

        Hello,

        You requested a {purpose} for your Forensic Agent account.

        Your 6-digit code is: {otp}

        This code will expire in 10 minutes.

        If you didn't request this code, please ignore this email.

        ---
        Autonomous Forensic Investigation Agent
        """

        # Log OTP for development
        logger.info(f"[OTP] Sending {purpose} code to {to_email}: {otp}")

        return self.send_email(to_email, subject, html_content, text_content)

    def send_welcome_email(self, to_email: str, username: str) -> bool:
        """Send welcome email to new users."""
        subject = "Welcome to Forensic Agent"

        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{ font-family: 'Segoe UI', Arial, sans-serif; background-color: #0a0f1a; color: #e0e0e0; }}
                .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                .header {{ background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }}
                .header h1 {{ color: #00ff88; margin: 0; font-size: 28px; }}
                .content {{ background: #1a1a2e; padding: 30px; border-radius: 0 0 10px 10px; }}
                .feature {{ background: #0f3460; padding: 15px; border-radius: 8px; margin: 10px 0; border-left: 4px solid #00ff88; }}
                .footer {{ text-align: center; margin-top: 20px; color: #666; font-size: 12px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🔬 Welcome to Forensic Agent</h1>
                </div>
                <div class="content">
                    <p>Hello <strong>{username}</strong>,</p>
                    <p>Welcome to the Autonomous Forensic Investigation Agent! Your account has been created successfully.</p>

                    <h3 style="color: #00ff88;">Key Features:</h3>

                    <div class="feature">
                        <strong>🤖 Autonomous Analysis</strong>
                        <p>Upload forensic artifacts and let our AI agent investigate automatically.</p>
                    </div>

                    <div class="feature">
                        <strong>🎯 MITRE ATT&CK Mapping</strong>
                        <p>All findings are mapped to MITRE ATT&CK techniques.</p>
                    </div>

                    <div class="feature">
                        <strong>💬 AI Chat Assistant</strong>
                        <p>Ask questions about your investigation in natural language.</p>
                    </div>

                    <div class="feature">
                        <strong>📊 Real-time Dashboard</strong>
                        <p>Monitor investigation progress with live updates.</p>
                    </div>

                    <p>Get started by uploading your first forensic artifact!</p>
                </div>
                <div class="footer">
                    <p>Autonomous Forensic Investigation Agent</p>
                </div>
            </div>
        </body>
        </html>
        """

        text_content = f"""
        Welcome to Forensic Agent!

        Hello {username},

        Welcome to the Autonomous Forensic Investigation Agent! Your account has been created successfully.

        Key Features:
        - Autonomous Analysis: Upload forensic artifacts and let our AI agent investigate automatically.
        - MITRE ATT&CK Mapping: All findings are mapped to MITRE ATT&CK techniques.
        - AI Chat Assistant: Ask questions about your investigation in natural language.
        - Real-time Dashboard: Monitor investigation progress with live updates.

        Get started by uploading your first forensic artifact!

        ---
        Autonomous Forensic Investigation Agent
        """

        return self.send_email(to_email, subject, html_content, text_content)


# Singleton instance
email_service = EmailService()
