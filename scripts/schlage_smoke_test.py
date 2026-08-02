#!/usr/bin/env python3
"""Safe smoke-test CLI for the unofficial pyschlage cloud integration.

Read operations are the default. Commands that change a lock require --apply.
The cleanup command can only delete access codes created with TEST_NAME_PREFIX.
"""

from __future__ import annotations

import argparse
from collections import Counter
from datetime import UTC, datetime, timedelta
from getpass import getpass
import os
from pathlib import Path
import secrets
import string
import sys
from typing import NoReturn

from pyschlage import Auth, Schlage
from pyschlage.code import AccessCode, TemporarySchedule
from pyschlage.exceptions import NotAuthorizedError, UnknownError


TEST_NAME_PREFIX = "FFH-TEST-"
DEFAULT_DURATION_MINUTES = 15
MIN_PIN_LENGTH = 4
MAX_PIN_LENGTH = 8
LOCAL_ENV_PATH = Path(__file__).resolve().parents[1] / ".env"


def fail(message: str, exit_code: int = 1) -> NoReturn:
    print(f"Error: {message}", file=sys.stderr)
    raise SystemExit(exit_code)


def load_local_env() -> None:
    """Load only the two supported credentials from the ignored local .env file."""
    if not LOCAL_ENV_PATH.is_file():
        return
    supported_keys = {"SCHLAGE_USERNAME", "SCHLAGE_PASSWORD"}
    for raw_line in LOCAL_ENV_PATH.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if key in supported_keys and key not in os.environ:
            os.environ[key] = value.strip()


def get_credentials() -> tuple[str, str]:
    """Read credentials without accepting them as command-line arguments."""
    username = os.getenv("SCHLAGE_USERNAME", "").strip()
    password = os.getenv("SCHLAGE_PASSWORD", "")

    if not username:
        username = input("Schlage account email: ").strip()
    if not password:
        password = getpass("Schlage account password: ")

    if not username or not password:
        fail("Schlage account email and password are required.", 2)
    return username, password


def connect() -> Schlage:
    username, password = get_credentials()
    auth = Auth(username, password)
    print("Authenticating with Schlage cloud…")
    auth.authenticate()
    return Schlage(auth)


def state_label(lock) -> str:
    if lock.is_jammed:
        return "jammed"
    if lock.is_locked is True:
        return "locked"
    if lock.is_locked is False:
        return "unlocked"
    return "unknown"


def short_id(device_id: str) -> str:
    return f"…{device_id[-8:]}" if len(device_id) > 8 else device_id


def print_locks(locks: list) -> None:
    if not locks:
        print("Authentication succeeded, but this account has no compatible locks.")
        return

    print(f"Authentication succeeded. Found {len(locks)} lock(s):")
    for index, lock in enumerate(locks, start=1):
        battery = "unknown" if lock.battery_level is None else f"{lock.battery_level}%"
        online = "online" if lock.connected else "offline"
        print(
            f"  [{index}] {lock.name} | {lock.model_name or lock.device_type} | "
            f"{online} | {state_label(lock)} | battery {battery} | "
            f"id {short_id(lock.device_id)}"
        )


def select_lock(locks: list, selector: str | None):
    if not locks:
        fail("No compatible locks were found for this account.")
    if selector is None:
        if len(locks) == 1:
            return locks[0]
        fail("More than one lock was found; pass --lock with its number, name, or ID.", 2)

    if selector.isdigit():
        index = int(selector) - 1
        if 0 <= index < len(locks):
            return locks[index]

    exact = [lock for lock in locks if selector in (lock.name, lock.device_id)]
    if len(exact) == 1:
        return exact[0]

    names = ", ".join(f"[{i}] {lock.name}" for i, lock in enumerate(locks, start=1))
    fail(f"Lock {selector!r} was not found. Available locks: {names}", 2)


def validate_pin(pin: str) -> str:
    if not pin.isascii() or not pin.isdigit():
        fail("PIN must contain ASCII digits only.", 2)
    if not MIN_PIN_LENGTH <= len(pin) <= MAX_PIN_LENGTH:
        fail(f"PIN length must be between {MIN_PIN_LENGTH} and {MAX_PIN_LENGTH} digits.", 2)
    return pin


def validate_test_name(name: str) -> str:
    if not name.startswith(TEST_NAME_PREFIX):
        fail(f"Test access-code names must start with {TEST_NAME_PREFIX!r}.", 2)
    if not name.isascii() or len(name) > 24:
        fail("Test access-code names must be ASCII and at most 24 characters.", 2)
    return name


def format_schedule(schedule) -> str:
    if isinstance(schedule, TemporarySchedule):
        return f"temporary {schedule.start.isoformat()} → {schedule.end.isoformat()}"
    if schedule is None:
        return "always"
    return "recurring"


def print_codes(lock) -> list[AccessCode]:
    codes = lock.get_access_codes()
    print(f"{lock.name} has {len(codes)} access code(s):")
    for code in codes:
        status = "disabled" if code.disabled else "enabled"
        print(
            f"  - {code.name} | {len(code.code)} digits (redacted) | "
            f"{status} | {format_schedule(code.schedule)}"
        )
    return codes


def pin_length_for(lock, requested_length: int | None) -> int:
    codes = lock.get_access_codes()
    if requested_length is not None:
        if not MIN_PIN_LENGTH <= requested_length <= MAX_PIN_LENGTH:
            fail(f"--length must be between {MIN_PIN_LENGTH} and {MAX_PIN_LENGTH}.", 2)
        return requested_length

    existing_lengths = Counter(len(code.code) for code in codes if code.code)
    if not existing_lengths:
        return MIN_PIN_LENGTH

    # Some current Encode locks report mixed PIN lengths even though older Schlage
    # documentation described a single length per lock. Default to the most common
    # existing length, preferring the shorter length on a tie.
    return min(existing_lengths, key=lambda length: (-existing_lengths[length], length))


def generate_unique_pin(lock, length: int) -> str:
    existing = {code.code for code in lock.get_access_codes()}
    for _ in range(100):
        candidate = "".join(secrets.choice(string.digits) for _ in range(length))
        if candidate not in existing:
            return candidate
    fail("Could not generate a unique PIN after 100 attempts.")


def run_check(client: Schlage, _args: argparse.Namespace) -> None:
    print_locks(client.locks())


def run_codes(client: Schlage, args: argparse.Namespace) -> None:
    lock = select_lock(client.locks(), args.lock)
    print_codes(lock)


def run_create(client: Schlage, args: argparse.Namespace) -> None:
    lock = select_lock(client.locks(), args.lock)
    if not lock.connected:
        fail(f"{lock.name} is offline; refusing to create a test PIN.")

    name = validate_test_name(args.name)
    pin_length = pin_length_for(lock, args.length)
    pin = validate_pin(args.pin) if args.pin else generate_unique_pin(lock, pin_length)
    if len(pin) != pin_length:
        fail(f"This lock uses {pin_length}-digit PINs, but the provided PIN has {len(pin)} digits.")

    existing_codes = lock.get_access_codes()
    if any(code.name == name for code in existing_codes):
        fail(f"An access code named {name!r} already exists.")
    if any(code.code == pin for code in existing_codes):
        fail("That PIN is already present on the lock.")

    start = datetime.now(UTC) - timedelta(minutes=1)
    end = start + timedelta(minutes=args.minutes + 1)
    print(f"Lock:       {lock.name}")
    print(f"Name:       {name}")
    print(f"Valid from: {start.isoformat()}")
    print(f"Valid until:{end.isoformat()}")
    print(f"PIN length: {len(pin)} digits")

    if not args.apply:
        print("Dry run only. Re-run with --apply to create the PIN.")
        return

    access_code = AccessCode(
        name=name,
        code=pin,
        schedule=TemporarySchedule(start=start, end=end),
        notify_on_use=False,
    )
    lock.add_access_code(access_code)
    print("Test PIN creation request succeeded.")
    print(f"PIN (shown once): {pin}")
    print(f"Access-code ID:   {access_code.access_code_id or 'not returned'}")
    print("After the test, delete it with the cleanup command even if it has expired.")


def run_cleanup(client: Schlage, args: argparse.Namespace) -> None:
    lock = select_lock(client.locks(), args.lock)
    name = validate_test_name(args.name)
    matches = [code for code in lock.get_access_codes() if code.name == name]
    if not matches:
        fail(f"No test access code named {name!r} exists on {lock.name}.")
    if len(matches) > 1:
        fail(f"Multiple codes named {name!r} were returned; refusing an ambiguous deletion.")

    print(f"Will delete test access code {name!r} from {lock.name}.")
    if not args.apply:
        print("Dry run only. Re-run with --apply to delete it.")
        return

    matches[0].delete()
    print("Test PIN deletion request succeeded.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Safely verify the unofficial pyschlage integration."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    check = subparsers.add_parser("check", help="Authenticate and list locks (read-only).")
    check.set_defaults(handler=run_check)

    codes = subparsers.add_parser("codes", help="List access-code metadata with PINs redacted.")
    codes.add_argument("--lock", help="Lock number, exact name, or device ID.")
    codes.set_defaults(handler=run_codes)

    create = subparsers.add_parser("create-test-pin", help="Create a short-lived test PIN.")
    create.add_argument("--lock", help="Lock number, exact name, or device ID.")
    create.add_argument("--name", default=f"{TEST_NAME_PREFIX}SMOKE")
    create.add_argument("--pin", help="Optional explicit PIN; generated securely when omitted.")
    create.add_argument("--length", type=int, help="PIN length when the lock has no existing PINs.")
    create.add_argument("--minutes", type=int, default=DEFAULT_DURATION_MINUTES)
    create.add_argument("--apply", action="store_true", help="Actually create the PIN.")
    create.set_defaults(handler=run_create)

    cleanup = subparsers.add_parser("cleanup", help="Delete one FFH-TEST- access code.")
    cleanup.add_argument("--lock", help="Lock number, exact name, or device ID.")
    cleanup.add_argument("--name", default=f"{TEST_NAME_PREFIX}SMOKE")
    cleanup.add_argument("--apply", action="store_true", help="Actually delete the PIN.")
    cleanup.set_defaults(handler=run_cleanup)
    return parser


def main() -> None:
    load_local_env()
    parser = build_parser()
    args = parser.parse_args()
    if getattr(args, "minutes", 1) <= 0:
        fail("--minutes must be greater than zero.", 2)
    try:
        client = connect()
        args.handler(client, args)
    except NotAuthorizedError:
        fail("Schlage rejected the account credentials.")
    except UnknownError as error:
        fail(f"Schlage cloud request failed: {error}")
    except KeyboardInterrupt:
        fail("Cancelled.", 130)


if __name__ == "__main__":
    main()
