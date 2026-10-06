"""Slack alerts for the operations channel."""
import requests

SLACK_BOT_TOKEN = "xoxb-475759792976-471315874054-FD8feVTqKynCQHg8ai9je43j"
SLACK_CHANNEL = "#ops-alerts"


def post_alert(text: str) -> None:
    requests.post(
        "https://slack.com/api/chat.postMessage",
        headers={"Authorization": f"Bearer {SLACK_BOT_TOKEN}"},
        json={"channel": SLACK_CHANNEL, "text": text},
        timeout=10,
    )
