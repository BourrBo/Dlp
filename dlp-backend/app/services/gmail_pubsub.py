import base64
import json

from google.cloud import pubsub_v1
from app.config import get_settings

def pull_gmail_notifications(max_messages: int = 10):
    settings = get_settings()
    if not settings.gcp_project_id or not settings.gmail_pubsub_subscription_id:
        raise RuntimeError("GCP_PROJECT_ID and GMAIL_PUBSUB_SUBSCRIPTION_ID must be configured")
    subscriber = pubsub_v1.SubscriberClient()

    subscription_path = subscriber.subscription_path(
        settings.gcp_project_id,
        settings.gmail_pubsub_subscription_id,
    )

    response = subscriber.pull(
        request={
            "subscription": subscription_path,
            "max_messages": max_messages,
        },
    )

    messages = []

    for received_message in response.received_messages:
        message = received_message.message

        notification = None

        if message.data:
            try:
                decoded = base64.urlsafe_b64decode(message.data).decode("utf-8")
                notification = json.loads(decoded)

                # Gmail Pub/Sub can sometimes deliver the notification
                # as a JSON string containing another JSON object.
                if isinstance(notification, str):
                    notification = json.loads(notification)

            except Exception:
                notification = {
                    "raw_data": message.data.decode("utf-8", errors="replace")
                }

        messages.append(
            {
                "ack_id": received_message.ack_id,
                "message_id": message.message_id,
                "publish_time": str(message.publish_time),
                "notification": notification,
            }
        )

    return messages
