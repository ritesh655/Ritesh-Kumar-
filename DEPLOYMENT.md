# GhostLeaks — Deployment Guide

## 0. First 24 hours — plain-language checklist

For a non-technical buyer standing this up for the first time. Do these
in order:

1. **Get your accounts ready** (10–15 min): RapidAPI account +
   BreachDirectory subscription (for breach lookups), a Brevo account
   (for sending emails), and a Postgres database (Render or Supabase both
   work). You need the API keys/connection string from each.
2. **Fill in the environment variables** (`.env.example` → your real
   `.env` or your host's environment settings panel). At minimum:
   `SECRET_KEY`, `DATABASE_URL`, `RAPIDAPI_KEY`, `BREVO_API_KEY`,
   `MAIL_USERNAME` (an email address you actually control — the app will
   refuse to send email rather than silently fall back to a placeholder
   address), `ALERT_SECRET`, `APP_PUBLIC_URL` (your real domain, once you
   have one).
3. **Deploy and load the app once** — confirms the database tables get
   created (`db.create_all()` runs automatically on boot).
4. **Create your own account** through `/register` — you'll automatically
   become the `owner` of a new workspace (tenant). Check your email and
   click the verification link.
5. **Set your branding** — go to Workspace Settings (`/admin/tenant-settings`)
   and set your company name, color, and logo. This is what your
   customers/employees will see instead of the default GhostLeaks look.
6. **If you're monitoring a company domain** — add it under the Domains
   tab, then publish the DNS TXT record it shows you at your DNS
   provider (Cloudflare, GoDaddy, Route53, whichever you use). DNS
   changes can take a few minutes to a couple of hours to show up
   worldwide — if "Check TXT" fails right away, wait 15–20 minutes and
   try again before assuming something's wrong.
7. **Set up the daily alert cron** — point your scheduler (Render Cron
   Job, GitHub Actions, cron-job.org, etc.) at
   `GET /send-breach-alerts` with header `X-Alert-Secret: <your ALERT_SECRET>`,
   once every 24 hours.
8. **Invite your team** — share the invite link shown on the Workspace
   Settings page; anyone who signs up through it joins your workspace,
   not a new one.

If something isn't working, check the application logs first — most
first-day issues are a missing or wrong environment variable, and the app
now logs those failures explicitly instead of failing silently.



Set all of these in your hosting provider's environment (Render, etc.) —
see `.env.example` for the full list:

| Variable | Purpose |
|---|---|
| `SECRET_KEY` | Flask session signing |
| `DATABASE_URL` | Postgres connection string (Supabase/Render Postgres) |
| `RAPIDAPI_KEY` | Shared server-wide breach-lookup API key |
| `BREVO_API_KEY` / `MAIL_USERNAME` | Transactional email sending |
| `RAZORPAY_KEY_ID` / `RAZORPAY_KEY_SECRET` | Payment processing |
| `ALERT_SECRET` | Shared secret protecting `/send-breach-alerts` (cron) |

## 2. Install & run

```
pip install -r requirements.txt
python app.py            # local dev, SQLite
# or, in production:
gunicorn app:app
```

`db.create_all()` runs automatically on startup and creates any tables
that don't exist yet. This is additive-only — it will NOT alter existing
tables. If you're upgrading an existing deployment from the previous
single-tenant version, see §4 below before deploying.

## 3. Domain monitoring — DNS setup (for your customers)

When a tenant admin adds a domain to monitor, they'll be shown a TXT
record to publish:

```
Host:  _ghostleaks-verify.<their-domain>
Type:  TXT
Value: ghostleaks-verify=<random-token-shown-in-dashboard>
```

Most DNS providers propagate TXT records within a few minutes, but allow
up to 24–48 hours before treating "not verified yet" as a real failure.
The verify button just re-checks live DNS — no waiting period is
hardcoded.

## 4. Upgrading an existing deployment (important)

The previous schema had no `tenant_id` on `User`/`ScanHistory`, and no
`Tenant`/`DomainMonitor`/`CredentialFinding`/`AuditLog` tables at all.
`db.create_all()` will create the new tables but will **not** add the new
`tenant_id` NOT NULL column to your existing `user`/`scan_history` tables
or backfill it — that will fail or leave rows inconsistent.

Recommended path for an existing production database:
1. Take a full backup first.
2. Manually create one `Tenant` row for your existing single-company
   deployment.
3. Add the `tenant_id` column to `user` and `scan_history` as nullable,
   backfill every existing row with that tenant's id, then (optionally)
   tighten to NOT NULL.
4. Run `db.create_all()` (or deploy normally) to create the remaining new
   tables.

This isn't scripted here because it depends on your current data — treat
it as a one-time manual migration, ideally with Alembic if you don't
already have it.

## 5. Multi-tenant white-label — operational notes

- Every new tenant is created with `plan='trial'` and default green
  branding; update via `/admin/tenant-settings` (owner-only).
- The invite link shown on that page
  (`/register?tenant_slug=<slug>`) is what you hand to a client company
  so their team joins their own isolated tenant.
- `RAPIDAPI_KEY` and all other provider keys are still server-wide,
  shared across every tenant on this deployment. If you're reselling this
  to multiple client companies, monitor your provider quota — many small
  tenants share the same quota pool. Per-tenant provider keys would be a
  reasonable next step if quota contention becomes a problem, but aren't
  implemented here.

## 6. Scheduled breach alerts

`GET /send-breach-alerts` with header `X-Alert-Secret: <ALERT_SECRET>` is
meant to be hit by an
external scheduler (Render Cron Job, GitHub Actions cron, etc.) once a
day. It iterates every paid, email-verified user across every tenant,
checks their email, and emails them only about *new* sources since their
last check. The secret is passed as a header, not a `?secret=` query
param, so it doesn't end up in server access logs, browser history, or
any proxy's request logs.
