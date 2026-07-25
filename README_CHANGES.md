# GhostLeaks — Rebuild Notes (July 22, 2026)

## Security fix (read this first)

The previous version returned actual leaked passwords to anyone who
looked up any email address, with no ownership verification, up to 100
at once via bulk CSV. That's removed. Every breach-check response now
returns source name + confidence + status only — never a credential
value. See `docs/ARCHITECTURE.md` §1 for the full explanation and why
this isn't optional.

## What's new

- **Credential status states** — findings now move through
  Active → Rotated / Historical / Accepted Risk / Resolved instead of a
  flat leaked/safe flag. (`docs/ARCHITECTURE.md` §2)
- **Domain monitoring** — track a whole company domain, gated behind DNS
  TXT ownership verification. (§3 — includes an honesty note on the
  underlying provider's real domain-search limits)
- **Exposure timeline** — `/timeline` visualizes when each exposure was
  discovered and when its status changed.
- **Confidence score & source correlation** — a small provider registry
  (`BREACH_PROVIDERS`) so findings confirmed by more than one source score
  higher. Only one provider is wired up today, so scores are honestly
  capped until a second is added. (§4)
- **Audit logs** — `/admin/audit-logs`, separate from per-user scan
  history: logins, status changes, domain actions, branding changes.
- **Multi-tenant white-label** — `Tenant` model, invite-link onboarding,
  per-tenant branding (name/color/logo) applied across dashboard, PDF
  reports, and email. (§6, §7)
- **Branding overhaul** — skull emoji and "dark web" framing removed;
  clean tenant-branded look.

## Deployment

See `docs/DEPLOYMENT.md` — in particular §4 if you're upgrading an
existing production database rather than starting fresh, since the new
`tenant_id` columns need a one-time manual backfill.

## Files

- `app.py` — Flask app (rewritten)
- `templates/` — includes new `findings.html`, `timeline.html`,
  `admin_audit.html`, `admin_tenant.html`, plus updated `dashboard.html`
  and `register.html`
- `docs/ARCHITECTURE.md`, `docs/DEPLOYMENT.md` — new
- `requirements.txt` — added `dnspython` (for domain TXT verification)
