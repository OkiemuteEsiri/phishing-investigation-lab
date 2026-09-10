from __future__ import annotations

import json
from pathlib import Path

from .models import MessageEvidence


def load_messages(path: str | Path) -> list[MessageEvidence]:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw, list):
        raise ValueError("input must be a JSON array")

    messages: list[MessageEvidence] = []
    seen: set[str] = set()
    for item in raw:
        if not isinstance(item, dict):
            raise ValueError("each message must be an object")
        message = MessageEvidence(
            message_id=item["message_id"],
            sender=item["sender"],
            recipient=item["recipient"],
            subject=item["subject"],
            received_at=item["received_at"],
            source_ip=item["source_ip"],
            spf=item["spf"],
            dkim=item["dkim"],
            dmarc=item["dmarc"],
            reply_to=item.get("reply_to"),
            urls=tuple(item.get("urls", [])),
            attachment_names=tuple(item.get("attachment_names", [])),
            user_clicked=bool(item.get("user_clicked", False)),
            user_submitted_credentials=bool(item.get("user_submitted_credentials", False)),
        )
        if message.message_id in seen:
            raise ValueError(f"duplicate message_id: {message.message_id}")
        seen.add(message.message_id)
        messages.append(message)
    return messages
