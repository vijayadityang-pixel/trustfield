"""
TrustField - Alert Notifier
Sends notifications for alerts and containment actions via multiple channels.
"""

import asyncio
import aiohttp
import logging
import smtplib
import json
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Any, Dict, List, Optional

from config import settings

logger = logging.getLogger(__name__)


class AlertNotifier:
    """
    Multi-channel notification system for TrustField alerts and containment events.
    Supports Slack, email (SMTP), and webhook (generic HTTP) delivery.
    """

    def __init__(self):
        self.slack_webhook_url: Optional[str] = getattr(settings, "SLACK_WEBHOOK_URL", None)
        self.smtp_host: str = getattr(settings, "SMTP_HOST", "localhost")
        self.smtp_port: int = getattr(settings, "SMTP_PORT", 587)
        self.smtp_username: Optional[str] = getattr(settings, "SMTP_USERNAME", None)
        self.smtp_password: Optional[str] = getattr(settings, "SMTP_PASSWORD", None)
        self.smtp_from: str = getattr(settings, "SMTP_FROM", "trustfield@example.com")
        self.notification_emails: List[str] = getattr(settings, "NOTIFICATION_EMAILS", [])
        self.generic_webhook_url: Optional[str] = getattr(settings, "GENERIC_WEBHOOK_URL", None)

    # ─── Slack ───────────────────────────────────────────────────────────────

    async def send_slack_notification(
        self,
        message: str,
        severity: str = "info",
        details: Optional[Dict] = None,
    ) -> bool:
        """
        Send a notification to Slack via incoming webhook.
        Color-codes by severity: critical=red, high=orange, medium=yellow, info=green.
        """
        if not self.slack_webhook_url:
            logger.debug("Slack webhook not configured, skipping")
            return False

        color_map = {
            "critical": "#FF0000",
            "high": "#FF6600",
            "medium": "#FFCC00",
            "low": "#00CCFF",
            "info": "#00CC00",
        }
        color = color_map.get(severity.lower(), "#CCCCCC")

        payload = {
            "attachments": [
                {
                    "color": color,
                    "title": f"TrustField [{severity.upper()}] Alert",
                    "text": message,
                    "fields": [
                        {"title": k, "value": str(v), "short": True}
                        for k, v in (details or {}).items()
                    ],
                    "footer": "TrustField Security Platform",
                }
            ]
        }

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self.slack_webhook_url,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=5),
                ) as resp:
                    if resp.status == 200:
                        logger.info("Slack notification sent")
                        return True
                    else:
                        logger.warning(f"Slack returned HTTP {resp.status}")
                        return False
        except Exception as exc:
            logger.error(f"Slack notification failed: {exc}")
            return False

    # ─── Email ───────────────────────────────────────────────────────────────

    async def send_email_notification(
        self,
        subject: str,
        body: str,
        recipients: Optional[List[str]] = None,
    ) -> bool:
        """Send an email notification via SMTP."""
        targets = recipients or self.notification_emails
        if not targets:
            logger.debug("No email recipients configured, skipping")
            return False

        def _send():
            msg = MIMEMultipart("alternative")
            msg["Subject"] = f"[TrustField] {subject}"
            msg["From"] = self.smtp_from
            msg["To"] = ", ".join(targets)
            msg.attach(MIMEText(body, "html"))

            with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                if self.smtp_username:
                    server.starttls()
                    server.login(self.smtp_username, self.smtp_password)
                server.sendmail(self.smtp_from, targets, msg.as_string())
            logger.info(f"Email sent to {targets}")
            return True

        try:
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(None, _send)
        except Exception as exc:
            logger.error(f"Email notification failed: {exc}")
            return False

    # ─── Generic Webhook ─────────────────────────────────────────────────────

    async def send_webhook_notification(self, payload: Dict) -> bool:
        """POST a JSON payload to the generic webhook URL (PagerDuty, Teams, etc.)."""
        if not self.generic_webhook_url:
            return False
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self.generic_webhook_url,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=5),
                ) as resp:
                    return resp.status < 300
        except Exception as exc:
            logger.error(f"Webhook notification failed: {exc}")
            return False

    # ─── High-level Helpers ───────────────────────────────────────────────────

    async def send_alert_notification(self, alert: Any) -> None:
        """Send multi-channel notification for a new alert."""
        severity = getattr(alert, "severity", "info")
        resource = getattr(alert, "resource_id", "unknown")
        message = (
            f"New {severity.upper()} alert detected on `{resource}` "
            f"(Provider: {getattr(alert, 'cloud_provider', 'N/A')})\n"
            f"{getattr(alert, 'description', '')}"
        )
        details = {
            "Alert ID": alert.id,
            "Resource": resource,
            "Provider": getattr(alert, "cloud_provider", "N/A"),
        }

        await asyncio.gather(
            self.send_slack_notification(message, severity=str(severity), details=details),
            self.send_email_notification(
                subject=f"[{severity.upper()}] New alert on {resource}",
                body=f"<h2>{message}</h2><pre>{json.dumps(details, indent=2)}</pre>",
            ),
            return_exceptions=True,
        )

    async def send_containment_notification(self, action: Any) -> None:
        """Notify stakeholders that a containment action was executed."""
        status = getattr(action, "status", "unknown")
        target = getattr(action, "target_resource", "unknown")
        action_type = getattr(action, "action_type", "unknown")

        message = (
            f"Containment action `{action_type}` on `{target}` "
            f"completed with status: **{status}**"
        )
        severity = "high" if str(status).upper() == "FAILED" else "info"

        await asyncio.gather(
            self.send_slack_notification(
                message,
                severity=severity,
                details={"Action ID": action.id, "Target": target, "Status": str(status)},
            ),
            return_exceptions=True,
        )