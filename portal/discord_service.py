from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping
from urllib.parse import urlparse

import requests


class DiscordNotificationError(RuntimeError):
    pass


EVENT_LABELS = {
    "integration_test": "Webhook 連線測試",
    "submitted": "收到新申請",
    "under_review": "申請進入審核",
    "interview_scheduled": "已安排面試",
    "interview_completed": "面試已完成",
    "approved": "申請已通過",
    "rejected": "申請未通過",
    "pin_issued": "臨時 PIN 已建立",
    "pin_failed": "臨時 PIN 建立失敗",
    "pin_revoked": "臨時 PIN 已撤銷",
    "pin_changed": "房客已更新自己的 PIN",
    "sponsor_approved": "房客已批准好友申請",
}

KIND_LABELS = {
    "visitor": "訪客申請",
    "temporary_resident": "暫住申請",
    "long_term_resident": "長期居民申請",
    "event": "活動報名",
}

EVENT_COLORS = {
    "submitted": 0xD9472B,
    "approved": 0x39725B,
    "rejected": 0x8D2E2E,
    "pin_failed": 0x8D2E2E,
    "pin_issued": 0xE2A039,
    "pin_revoked": 0x626579,
}


def _clean(value: Any, limit: int = 900) -> str:
    text = str(value or "—").replace("`", "ˋ").replace("@", "＠")
    return text[:limit]


@dataclass(frozen=True)
class DiscordNotifier:
    webhook_url: str
    timeout_seconds: float = 5.0

    def __post_init__(self) -> None:
        if not self.webhook_url:
            return
        parsed = urlparse(self.webhook_url)
        if (
            parsed.scheme != "https"
            or parsed.hostname not in {"discord.com", "discordapp.com"}
            or not parsed.path.startswith("/api/webhooks/")
        ):
            raise ValueError("DISCORD_WEBHOOK_URL must be an official Discord webhook URL.")

    def send(
        self,
        event_type: str,
        application: Mapping[str, Any],
        detail: str = "",
        admin_url: str = "",
    ) -> bool:
        if not self.webhook_url:
            return False

        period = " — ".join(
            filter(None, [application.get("requested_start"), application.get("requested_end")])
        )
        fields = [
            {
                "name": "申請類型",
                "value": _clean(KIND_LABELS.get(application.get("kind"), application.get("kind"))),
                "inline": True,
            },
            {
                "name": "狀態",
                "value": _clean(application.get("status")),
                "inline": True,
            },
            {
                "name": "申請人",
                "value": _clean(f"{application.get('full_name', '')}\n{application.get('email', '')}"),
                "inline": False,
            },
        ]
        if period:
            fields.append({"name": "申請期間", "value": _clean(period), "inline": False})
        if detail:
            fields.append({"name": "更新內容", "value": _clean(detail), "inline": False})

        embed: dict[str, Any] = {
            "title": EVENT_LABELS.get(event_type, event_type),
            "color": EVENT_COLORS.get(event_type, 0x23283B),
            "fields": fields,
            "footer": {"text": "Formosa Founders House"},
        }
        if admin_url:
            embed["url"] = admin_url

        try:
            response = requests.post(
                self.webhook_url,
                params={"wait": "true"},
                json={
                    "username": "FFH Applications",
                    "allowed_mentions": {"parse": []},
                    "embeds": [embed],
                },
                timeout=self.timeout_seconds,
            )
            response.raise_for_status()
        except requests.RequestException as error:
            raise DiscordNotificationError("Discord rejected or did not receive the notification.") from error
        return True
