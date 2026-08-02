from __future__ import annotations

from types import SimpleNamespace
import unittest

from scripts.schlage_smoke_test import pin_length_for, select_lock, short_id, state_label


class SchlageSmokeTestUnitTests(unittest.TestCase):
    def setUp(self) -> None:
        self.front = SimpleNamespace(
            name="Front Door",
            device_id="device-1234567890",
            is_jammed=False,
            is_locked=True,
        )
        self.back = SimpleNamespace(
            name="Back Door",
            device_id="device-0987654321",
            is_jammed=False,
            is_locked=False,
        )
        self.locks = [self.front, self.back]

    def test_select_lock_by_number_name_and_id(self) -> None:
        self.assertIs(select_lock(self.locks, "1"), self.front)
        self.assertIs(select_lock(self.locks, "Back Door"), self.back)
        self.assertIs(select_lock(self.locks, self.front.device_id), self.front)

    def test_selects_only_lock_without_selector(self) -> None:
        self.assertIs(select_lock([self.front], None), self.front)

    def test_state_labels(self) -> None:
        self.assertEqual(state_label(self.front), "locked")
        self.assertEqual(state_label(self.back), "unlocked")
        self.front.is_jammed = True
        self.assertEqual(state_label(self.front), "jammed")

    def test_short_id_does_not_expose_full_device_id(self) -> None:
        result = short_id(self.front.device_id)
        self.assertEqual(result, "…34567890")
        self.assertNotIn(self.front.device_id, result)

    def test_pin_length_uses_most_common_existing_length(self) -> None:
        lock = SimpleNamespace(
            get_access_codes=lambda: [
                SimpleNamespace(code="1234"),
                SimpleNamespace(code="123456"),
                SimpleNamespace(code="5678"),
            ]
        )
        self.assertEqual(pin_length_for(lock, None), 4)
        self.assertEqual(pin_length_for(lock, 6), 6)


if __name__ == "__main__":
    unittest.main()
