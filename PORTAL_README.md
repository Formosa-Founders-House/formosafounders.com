# Formosa House application portal

The portal adds persistent applications, administrator review workflows, interviews,
final decisions, private applicant status pages, and temporary Schlage PINs to the
existing Formosa Founders House website.

## Local start

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/flask --app wsgi run --host 127.0.0.1 --port 5050
```

Open:

- Public application chooser: `http://127.0.0.1:5050/apply`
- Google sign-in: `http://127.0.0.1:5050/login`

Google OpenID Connect is the single sign-in path for applicants, residents, visitors,
and administrators. Configure `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, and the exact
`GOOGLE_REDIRECT_URI`. The production callback is
`https://www.formosafounders.com/auth/google/callback`.

The verified Google email in `ADMIN_EMAIL` receives the administrator navigation item.
Approved temporary and long-term residents receive resident access; approved visitor
and event applications receive visitor access. These roles are always derived on the
server from approved records.

## Workflows

All four application types require a final decision:

- Visitor: submitted → under review → approved/rejected
- Event: submitted → under review → approved/rejected
- Temporary resident: submitted → under review → interview → approved/rejected
- Long-term resident: submitted → under review → interview → approved/rejected

Applicants receive a private, unguessable status URL after submission. The page shows
the current stage, scheduled interview, final decision, and—when issued—an encrypted-at-
rest temporary PIN.

Signed-in applicants get a reusable profile. The first submitted application saves the
name, phone, personal link, and background, then later forms prefill those fields.

Residents can see only lock events associated with their own Schlage access-code ID and
can change only their own linked PIN. A resident friend must apply through that
resident's invite link; resident approval is an endorsement, while the House team keeps
the final approval and PIN issuance decision.

## Discord notifications

Set `DISCORD_WEBHOOK_URL` to receive Discord embeds when an application is submitted,
reviewed, scheduled for or completes an interview, approved/rejected, or has a PIN
issued, failed, or revoked. Notifications include an administrator link but never the
temporary PIN itself. A Discord outage does not interrupt the application workflow.

## Door access

PINs are only issued from an approved application. The administrator chooses the exact
validity window before the server calls the unofficial `pyschlage` integration. PINs can
also be revoked immediately from the application detail page.

The Schlage account password, admin password hash, session signing key, and PIN
encryption key live only in the ignored local `.env` file. Never commit or copy that
file into an image.

## Database

Local development falls back to SQLite under `instance/`. When `DATABASE_URL` is set,
the portal uses the linked Neon PostgreSQL database instead. Apply the production schema
and copy any existing local records with:

```bash
.venv/bin/python scripts/migrate_to_postgres.py
```

For Vercel, use the pooled Neon `DATABASE_URL` and store it with the other runtime
secrets. Production also needs HTTPS, login rate limiting at the edge, monitoring, and a
manual Schlage Home fallback.

Current production entry point: `https://www.formosafounders.com/`.

## Tests

```bash
.venv/bin/python -m unittest discover -s tests -v
```

The test suite covers public submission, private status pages, the mandatory interview
gate, final approval, PIN encryption, issuance, and revocation without touching the real
lock.
