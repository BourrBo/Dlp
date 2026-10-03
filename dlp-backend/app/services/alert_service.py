import httpx

from app.config import get_settings

def send_alert(
    decision: str,
    data_type: str,
    filename: str | None = None,
    destination: str | None = None,
    reason: str | None = None,
):
    # Only alert on BLOCK or WARN.
    if decision not in {"block", "warn"}:
        return {
            "sent": False,
            "reason": "No alert required",
        }

    webhook_url = get_settings().slack_webhook_url

    if not webhook_url:
        return {
            "sent": False,
            "reason": "Slack webhook is not configured",
        }

    message = {
        "text": (
            f"🚨 DLP {decision.upper()}\n"
            f"Data type: {data_type}\n"
            f"File: {filename or 'N/A'}\n"
            f"Destination: {destination or 'N/A'}\n"
            f"Reason: {reason or 'N/A'}"
        )
    }

    try:
        response = httpx.post(webhook_url, json=message, timeout=10.0)
        response.raise_for_status()
        return {"sent": True, "status_code": response.status_code}
    except httpx.HTTPError:
        return {
            "sent": False,
            "reason": "Slack webhook request failed",
        }
