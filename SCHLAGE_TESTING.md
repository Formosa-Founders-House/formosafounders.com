# Schlage smoke test

This is a deliberately small test of the unofficial `pyschlage` cloud integration.
It must pass before the visitor application and administration workflow depend on it.

## Safety properties

- Credentials are prompted locally and are never written to this repository.
- Read commands redact every PIN and most of each device ID.
- Commands that change lock data are dry runs unless `--apply` is provided.
- Cleanup can only delete access codes whose names begin with `FFH-TEST-`.
- The tool does not expose a remote-unlock command.

## Install

From the project directory:

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements-schlage.txt
```

## 1. Check authentication and discover locks

```bash
.venv/bin/python scripts/schlage_smoke_test.py check
```

Enter the email address and password used by the Schlage Home app. The password input
is hidden. If the account has multiple locks, note the number shown next to the lock
that should be tested.

For unattended local use, the same values can be supplied as `SCHLAGE_USERNAME` and
`SCHLAGE_PASSWORD` environment variables. Do not add them to `.env` or commit them.

## 2. Read access-code metadata

For an account with one lock:

```bash
.venv/bin/python scripts/schlage_smoke_test.py codes
```

For an account with multiple locks:

```bash
.venv/bin/python scripts/schlage_smoke_test.py codes --lock 1
```

The real PIN values are always redacted.

## 3. Preview a 15-minute temporary PIN

```bash
.venv/bin/python scripts/schlage_smoke_test.py create-test-pin --lock 1
```

This is a dry run. It checks connectivity, existing PIN metadata, name collisions, and
PIN collisions, but does not change the lock.

## 4. Create and physically verify the temporary PIN

Only run this while someone is at the door and has a physical key available:

```bash
.venv/bin/python scripts/schlage_smoke_test.py create-test-pin --lock 1 --apply
```

The generated PIN is printed once. Verify that it unlocks the door, then verify that
it stops working after the expiration time. An expired code still occupies a slot on
the lock until it is deleted.

## 5. Remove the test PIN

Preview deletion:

```bash
.venv/bin/python scripts/schlage_smoke_test.py cleanup --lock 1
```

Delete it:

```bash
.venv/bin/python scripts/schlage_smoke_test.py cleanup --lock 1 --apply
```

## Pass criteria

The integration is suitable for the first application prototype when all of these are
true:

1. Authentication and lock discovery succeed repeatedly.
2. Existing access-code metadata can be read without errors.
3. The generated temporary PIN appears in the Schlage Home app.
4. The PIN works during its window and fails after expiration.
5. Cleanup removes the PIN from both the app and the physical lock.

This remains an unofficial cloud integration. A production administration system must
therefore keep a manual Schlage Home fallback, audit every PIN change, limit admin
access, and tolerate API outages.
