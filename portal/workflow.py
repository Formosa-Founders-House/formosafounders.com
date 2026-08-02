from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ApplicationKind:
    key: str
    title: str
    english: str
    description: str
    interview_required: bool
    pin_eligible: bool


APPLICATION_KINDS = {
    "visitor": ApplicationKind(
        "visitor",
        "訪客申請",
        "Visitor request",
        "短時間拜訪、參觀或與屋內成員會面。",
        False,
        True,
    ),
    "temporary_resident": ApplicationKind(
        "temporary_resident",
        "暫住申請",
        "Short stay",
        "短期住進 Formosa House；通過初審後需要面談。",
        True,
        True,
    ),
    "long_term_resident": ApplicationKind(
        "long_term_resident",
        "長期居民申請",
        "Resident application",
        "申請成為長期居民；包含初審、面談與最終決定。",
        True,
        True,
    ),
    "event": ApplicationKind(
        "event",
        "活動報名",
        "Event registration",
        "參加 Formosa House 活動；核准後可取得活動時段臨時 PIN。",
        False,
        True,
    ),
}


STATUS_LABELS = {
    "submitted": "已送出",
    "under_review": "審核中",
    "interview_scheduled": "面試已安排",
    "interview_completed": "面試完成",
    "approved": "已通過",
    "rejected": "未通過",
    "withdrawn": "已撤回",
}


def can_approve(application, interview) -> bool:
    if not application["interview_required"]:
        return application["status"] in {"submitted", "under_review"}
    return bool(interview and interview["status"] == "completed")
