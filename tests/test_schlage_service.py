from datetime import UTC, datetime
import unittest
from zoneinfo import ZoneInfo

from portal.schlage_service import SchlagePinService


PACIFIC = ZoneInfo("America/Los_Angeles")


class FakeLock:
    name = "Front Door"

    def __init__(self) -> None:
        self.added = []

    def get_access_codes(self):
        return []

    def add_access_code(self, access_code):
        self.added.append(access_code)


class SchlageScheduleTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.lock = FakeLock()
        self.service = SchlagePinService()
        self.service._lock = lambda: self.lock

    def issue(self, start: datetime, end: datetime):
        self.service.issue("FFH-TEST", start, end)
        return self.lock.added[0].schedule

    def test_summer_schedule_keeps_pacific_wall_time(self) -> None:
        schedule = self.issue(
            datetime(2026, 8, 1, 12, 50, tzinfo=PACIFIC),
            datetime(2026, 8, 1, 23, 59, tzinfo=PACIFIC),
        )

        self.assertEqual(schedule.start, datetime(2026, 8, 1, 12, 50, tzinfo=UTC))
        self.assertEqual(schedule.end, datetime(2026, 8, 1, 23, 59, tzinfo=UTC))

    def test_winter_schedule_keeps_pacific_wall_time(self) -> None:
        schedule = self.issue(
            datetime(2026, 12, 1, 12, 50, tzinfo=PACIFIC),
            datetime(2026, 12, 1, 23, 59, tzinfo=PACIFIC),
        )

        self.assertEqual(schedule.start, datetime(2026, 12, 1, 12, 50, tzinfo=UTC))
        self.assertEqual(schedule.end, datetime(2026, 12, 1, 23, 59, tzinfo=UTC))


if __name__ == "__main__":
    unittest.main()
