# GhostLeaks — Architecture

## 1. The security fix this rebuild is built on

The previous version's `check_email_breach()` returned the actual leaked
password for any email address a user submitted — including other people's
emails, with no ownership check, up to 100 at a time via bulk CSV upload.
That's not a breach-notification feature, it's a plaintext credential
lookup tool, and it's the one thing this rebuild does not preserve.

**What changed:**
- Every breach-checking code path (`/check-email`, `/bulk-check`,
  `/api/v1/check-email`, the scheduled alert job) now returns only:
  `source name`, `confidence score`, and `status`. No password, no hash,
  no credential value, ever leaves the provider response.
- This is enforced at the lowest layer: `provider_breachdirectory()` reads
  `item.get('sources')` and explicitly does **not** read
  `item.get('password')`. There's a comment there for exactly this reason
  — don't remove that filtering without re-reading this section.

This is the one non-negotiable part of the whole rebuild. Everything else
below is a normal SaaS feature built on top of that fixed foundation.

## 2. Credential status states

`CredentialFinding.status` replaces the old binary leaked/safe result with
a lifecycle:

| Status | Meaning |
|---|---|
| `active` | Newly discovered, nothing done yet |
| `rotated` | The password/credential has been changed |
| `historical` | Old breach, exposure is stale/dead |
| `accepted_risk` | Reviewed and consciously left as-is |
| `resolved` | Fully remediated |

A finding is upserted (not duplicated) on every scan, keyed on
`(tenant_id, email, source_name)` — re-scanning the same email against the
same breach source updates `last_seen` and confidence rather than creating
a new row, so status history survives repeat scans.

## 3. Domain monitoring + ownership verification

`DomainMonitor` lets a tenant track a whole company domain instead of one
email at a time. Because a domain-wide scan can surface exposure data
about many people at once, it's gated behind DNS ownership proof:

1. Admin adds a domain → gets a random `verification_token`.
2. Admin publishes a TXT record: `_ghostleaks-verify.<domain>` =
   `ghostleaks-verify=<token>`.
3. `/domains/<id>/verify` does a live DNS TXT lookup (via `dnspython`) and
   only flips `verified=True` if the token matches.
4. `/domains/<id>/scan` refuses to run against an unverified domain.

**Honesty note on domain-scan quality:** BreachDirectory's public API
(the only email-breach provider wired up today) is fundamentally an
email/username lookup service, not a true domain-wide breach index. The
domain scan endpoint passes the domain itself as a search term as a
best-effort measure, but for real enterprise-grade domain monitoring
you'd want a provider that supports domain-scoped queries natively (e.g.
an enterprise breach-intel vendor). The architecture (provider registry +
verification gate) is ready for that; the current single provider isn't
built for it. Don't oversell this to a paying customer as full domain
enumeration until a real domain-search provider is plugged in.

## 4. Confidence score & source correlation

`BREACH_PROVIDERS` is a small registry of provider functions — right now
it has exactly one entry (BreachDirectory). `aggregate_breach_sources()`
calls every configured provider and tallies how many of them reported the
same source name for the same email (`confirmed_by`).

`compute_confidence()`:
- Base score per hit: 60 (single-source finding)
- +20 per additional confirming source, capped at +40
- +5 if the exposure has been outstanding >365 days (staleness signal)

**Honesty note:** with one provider configured, nothing can be
cross-confirmed, so every finding currently caps at 60–65. That's correct
behavior, not a bug — it's telling you the truth about single-source
confidence. Adding a second/third provider to `BREACH_PROVIDERS` is what
unlocks the higher-confidence tier; there's no shortcut around that
without misrepresenting confidence you don't actually have.

## 5. Audit logs vs. scan history

These are deliberately two different tables:
- `ScanHistory` — what was scanned, by whom, when, leaked or not. User-facing.
- `AuditLog` — administrative/state-changing actions: logins, status
  changes, domain add/verify/scan, branding changes, API key rotation.
  Admin/owner-facing only (`/admin/audit-logs`), scoped to the tenant.

## 6. Multi-tenancy

`Tenant` is the isolation boundary. Every row that matters
(`User`, `ScanHistory`, `CredentialFinding`, `DomainMonitor`, `AuditLog`)
carries a `tenant_id`, and every query in `app.py` filters by
`current_user.tenant_id` (or `request.api_user.tenant_id` for the API).

**The rule for anyone extending this app:** if you add a new model or
query, it must be scoped by `tenant_id`. There is currently no
database-level enforcement of this (e.g. no Postgres row-level security)
— it's enforced by code convention only. For a production white-label
deployment serving multiple untrusted client companies, adding Postgres
RLS policies as a second line of defense is a reasonable next step; this
rebuild does not include that.

Onboarding: registering without a `tenant_slug` creates a brand-new
tenant (the user becomes its `owner`). Registering with a `tenant_slug`
(from an admin's invite link, see Workspace Settings) joins that existing
tenant as a `member`. There's no cross-tenant data access anywhere in the
UI or API.

## 7. Branding overhaul

Removed: skull emoji in emails/PDF titles, "Dark Web Breach Intelligence"
framing. Each tenant now has `brand_name`, `primary_color`, and
`logo_url`, injected into every authenticated template via the
`inject_brand()` context processor and used in the PDF report generator.
Pre-login pages (landing/login/register/pricing) intentionally keep the
default GhostLeaks operator branding, since tenant identity isn't known
until a user logs in — true per-tenant subdomains/branded auth pages
would be a further step, not included here.

## 8. What's out of scope / known gaps

- No Alembic migrations — `db.create_all()` on boot, same as before.
  Fine for a new deployment; for an existing production DB with real
  data, you'll want a real migration for the new tables/columns.
- No Postgres row-level security (see §6).
- Domain-wide scanning quality is capped by the underlying provider (§3).
- Audit log UI shows actor by user ID, not name — fine for v1, a quick
  join to `User.name` would improve it.
