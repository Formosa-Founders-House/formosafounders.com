from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime
import os
import secrets
import string
from zoneinfo import ZoneInfo

from pyschlage import Auth, Schlage
from pyschlage.code import AccessCode, TemporarySchedule
from pyschlage.exceptions import Error as SchlageError


class PinIntegrationError(RuntimeError):
    pass


LOCK_TIMEZONE = ZoneInfo("America/Los_Angeles")


def schlage_wall_time(value: datetime) -> datetime:
    """Encode a lock-local wall time for Schlage's temporary schedule API.

    Schlage interprets the epoch's clock fields in the lock's configured timezone.
    Keeping the Pacific wall-clock fields while marking them UTC prevents a second
    timezone conversion in Schlage Home. ZoneInfo still handles PST/PDT for us.
    """
    local_value = value.astimezone(LOCK_TIMEZONE)
    return local_value.replace(tzinfo=UTC)


@dataclass(frozen=True)
class IssuedPin:
    pin: str
    access_code_id: str | None
    access_code_name: str
    lock_name: str


@dataclass(frozen=True)
class ResidentAccessLog:
    created_at: datetime
    message: str
    lock_name: str


class SchlagePinService:
    """Small server-only boundary around the unofficial Schlage cloud client."""

    def _lock(self):
        username = os.getenv("SCHLAGE_USERNAME", "").strip()
        password = os.getenv("SCHLAGE_PASSWORD", "")
        selector = os.getenv("SCHLAGE_LOCK_SELECTOR", "").strip()
        if not username or not password:
            raise PinIntegrationError("Schlage credentials are not configured.")

        try:
            auth = Auth(username, password)
            auth.authenticate()
            locks = Schlage(auth).locks()
        except SchlageError as error:
            raise PinIntegrationError("Schlage authentication or discovery failed.") from error

        if selector:
            matches = [lock for lock in locks if selector in (lock.name, lock.device_id)]
            if len(matches) == 1:
                lock = matches[0]
            else:
                raise PinIntegrationError("Configured Schlage lock was not found uniquely.")
        elif len(locks) == 1:
            lock = locks[0]
        else:
            raise PinIntegrationError("A unique Schlage lock is not configured.")

        if not lock.connected:
            raise PinIntegrationError("The configured Schlage lock is offline.")
        return lock

    @staticmethod
    def _pin_length(codes: list[AccessCode]) -> int:
        lengths = Counter(len(code.code) for code in codes if code.code)
        if not lengths:
            return 4
        return min(lengths, key=lambda length: (-lengths[length], length))

    @staticmethod
    def _unique_pin(codes: list[AccessCode], length: int) -> str:
        existing = {code.code for code in codes}
        for _ in range(100):
            candidate = "".join(secrets.choice(string.digits) for _ in range(length))
            if candidate not in existing:
                return candidate
        raise PinIntegrationError("Unable to generate a unique PIN.")

    def issue(self, access_code_name: str, valid_from: datetime, valid_until: datetime) -> IssuedPin:
        if valid_from.tzinfo is None or valid_until.tzinfo is None:
            raise PinIntegrationError("PIN schedule must include a timezone.")
        if valid_until <= valid_from:
            raise PinIntegrationError("PIN expiration must be after its start time.")
        if not access_code_name.isascii() or len(access_code_name) > 24:
            raise PinIntegrationError("PIN label must be ASCII and at most 24 characters.")

        lock = self._lock()
        try:
            codes = lock.get_access_codes()
            if any(code.name == access_code_name for code in codes):
                raise PinIntegrationError("A Schlage PIN with this label already exists.")
            pin = self._unique_pin(codes, self._pin_length(codes))
            access_code = AccessCode(
                name=access_code_name,
                code=pin,
                schedule=TemporarySchedule(
                    start=schlage_wall_time(valid_from),
                    end=schlage_wall_time(valid_until),
                ),
                notify_on_use=False,
            )
            lock.add_access_code(access_code)
        except SchlageError as error:
            raise PinIntegrationError("Schlage rejected the temporary PIN request.") from error

        return IssuedPin(
            pin=pin,
            access_code_id=access_code.access_code_id,
            access_code_name=access_code_name,
            lock_name=lock.name,
        )

    def revoke(self, access_code_id: str | None, access_code_name: str) -> None:
        lock = self._lock()
        try:
            codes = lock.get_access_codes()
            matches = [
                code
                for code in codes
                if (access_code_id and code.access_code_id == access_code_id)
                or code.name == access_code_name
            ]
            if not matches:
                return
            if len(matches) > 1:
                raise PinIntegrationError("Schlage returned multiple matching PINs.")
            matches[0].delete()
        except SchlageError as error:
            raise PinIntegrationError("Schlage rejected the PIN removal request.") from error

    def change_pin(
        self,
        access_code_id: str | None,
        access_code_name: str,
        new_pin: str,
    ) -> str:
        if not new_pin.isdigit() or not 4 <= len(new_pin) <= 8:
            raise PinIntegrationError("PIN 必須是 4 到 8 位數字。")
        lock = self._lock()
        try:
            codes = lock.get_access_codes()
            matches = [
                code
                for code in codes
                if (access_code_id and code.access_code_id == access_code_id)
                or code.name == access_code_name
            ]
            if len(matches) != 1:
                raise PinIntegrationError("找不到唯一對應的房客 PIN。")
            target = matches[0]
            if len(new_pin) != len(target.code):
                raise PinIntegrationError(f"這把鎖需要 {len(target.code)} 位數 PIN。")
            if any(code.code == new_pin and code.access_code_id != target.access_code_id for code in codes):
                raise PinIntegrationError("這組 PIN 已被使用，請選擇其他數字。")
            target.code = new_pin
            target.save()
        except SchlageError as error:
            raise PinIntegrationError("Schlage 拒絕更新房客 PIN。") from error
        return lock.name

    def access_logs(
        self,
        access_code_ids: set[str],
        limit: int = 50,
    ) -> list[ResidentAccessLog]:
        if not access_code_ids:
            return []
        lock = self._lock()
        try:
            logs = lock.logs(limit=min(max(limit * 4, 50), 200), sort_desc=True)
        except SchlageError as error:
            raise PinIntegrationError("目前無法讀取 Schlage 進出紀錄。") from error
        return [
            ResidentAccessLog(log.created_at, log.message, lock.name)
            for log in logs
            if log.access_code_id in access_code_ids
        ][:limit]
