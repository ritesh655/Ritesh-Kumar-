import hashlib
import requests
import os
import time
import json
import secrets
import socket
import ipaddress
import logging
from urllib.parse import urlparse
from xml.sax.saxutils import escape as xml_escape
from datetime import datetime, date
from io import BytesIO
from functools import wraps
from flask import Flask, request, jsonify, render_template, redirect, url_for, flash, session, send_file, g
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect, generate_csrf
from dotenv import load_dotenv
from itsdangerous import URLSafeTimedSerializer
import sib_api_v3_sdk
from sib_api_v3_sdk.rest import ApiException
import razorpay

try:
    import dns.resolver  # dnspython — used for domain-ownership TXT verification
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

load_dotenv()

RAZORPAY_KEY_ID     = os.environ.get('RAZORPAY_KEY_ID', '')
RAZORPAY_KEY_SECRET = os.environ.get('RAZORPAY_KEY_SECRET', '')
PLAN_AMOUNT         = 49900
RAPIDAPI_KEY        = os.environ.get('RAPIDAPI_KEY', '')
MAIL_FROM_ADDRESS   = os.environ.get('MAIL_USERNAME', '')
APP_PUBLIC_URL      = os.environ.get('APP_PUBLIC_URL', '')  # e.g. https://portal.yourcompany.com

# Breach data provider selection — see providers/ and docs/ARCHITECTURE.md.
# BREACH_PROVIDER may be a single name or a comma-separated list (to keep
# the existing cross-provider confirmation behavior in
# aggregate_breach_sources). Defaults to 'breachdirectory' so existing
# deployments that only set RAPIDAPI_KEY keep working with zero config
# changes.
BREACH_PROVIDER     = os.environ.get('BREACH_PROVIDER', 'breachdirectory')
HIBP_API_KEY        = os.environ.get('HIBP_API_KEY', '')
LEAKCHECK_API_KEY   = os.environ.get('LEAKCHECK_API_KEY', '')
XPOSEDORNOT_API_KEY = os.environ.get('XPOSEDORNOT_API_KEY', '')

# ─────────────────────────────────────────────────────────
# Credential status states — see docs/ARCHITECTURE.md
# ─────────────────────────────────────────────────────────
STATUS_ACTIVE         = 'active'          # newly found, nothing done yet
STATUS_ROTATED        = 'rotated'         # password/credential has been changed
STATUS_HISTORICAL     = 'historical'      # old breach, credential long since dead
STATUS_ACCEPTED_RISK  = 'accepted_risk'   # reviewed, consciously left as-is
STATUS_RESOLVED       = 'resolved'        # fully remediated / closed out
VALID_STATUSES = [STATUS_ACTIVE, STATUS_ROTATED, STATUS_HISTORICAL, STATUS_ACCEPTED_RISK, STATUS_RESOLVED]

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s [%(name)s] %(message)s'
)
logger = logging.getLogger('ghostleaks')

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'change-this-in-production')
if app.config['SECRET_KEY'] == 'change-this-in-production':
    logging.getLogger('ghostleaks').warning(
        "SECRET_KEY is not set in the environment — using an insecure default. "
        "Set SECRET_KEY in your host's Environment Variables before real users sign up, "
        "or every login/password-reset token becomes forgeable."
    )

database_url = os.environ.get('DATABASE_URL', 'sqlite:///users.db')
if database_url.startswith('postgres://'):
    database_url = database_url.replace('postgres://', 'postgresql://', 1)
app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Session cookie hardening. SESSION_COOKIE_SECURE requires the app actually
# be served over HTTPS (true on Render/most hosts) — if you're testing over
# plain http:// locally, temporarily set this False or the login cookie
# won't be sent back by the browser.
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('FLASK_ENV') != 'development'

# Adds X-RateLimit-Limit / X-RateLimit-Remaining / X-RateLimit-Reset and
# Retry-After headers on every response (and specifically on 429s) — API
# integrators (MSPs) need these to back off correctly instead of guessing.
app.config['RATELIMIT_HEADERS_ENABLED'] = True

# Caps the whole request body (covers the bulk CSV upload) so a large file
# can't be used to exhaust memory/CPU. Flask returns a 413 automatically
# for anything over this before the view function even runs.
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024  # 2 MB

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please login to access this page.'
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])

limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["500 per day", "100 per hour"],
    storage_uri="memory://"
)

csrf = CSRFProtect(app)

@app.context_processor
def inject_csrf_token():
    return dict(csrf_token=generate_csrf)

# ─────────────────────────────────────────────────────────
# Models
# ─────────────────────────────────────────────────────────

class Tenant(db.Model):
    """A single client company on a multi-tenant deployment.
    Every user, domain, finding, and audit log row belongs to exactly one
    tenant. All queries in this app MUST filter by tenant_id — see
    docs/ARCHITECTURE.md 'Tenant isolation' section for the rule and why."""
    id            = db.Column(db.Integer, primary_key=True)
    name          = db.Column(db.String(150), nullable=False)
    slug          = db.Column(db.String(80), unique=True, nullable=False)
    brand_name    = db.Column(db.String(100), default='GhostLeaks')
    primary_color = db.Column(db.String(7), default='#3ddc97')   # hex color
    logo_url      = db.Column(db.String(500), nullable=True)
    plan          = db.Column(db.String(30), default='trial')
    created_at    = db.Column(db.DateTime, default=datetime.utcnow)
    users         = db.relationship('User', backref='tenant', lazy=True)


class User(UserMixin, db.Model):
    id                  = db.Column(db.Integer, primary_key=True)
    tenant_id           = db.Column(db.Integer, db.ForeignKey('tenant.id'), nullable=False)
    role                = db.Column(db.String(20), default='member')  # owner | admin | member
    name                = db.Column(db.String(100), nullable=False)
    email               = db.Column(db.String(150), unique=True, nullable=False)
    email_verified      = db.Column(db.Boolean, default=False)
    password            = db.Column(db.String(200), nullable=False)
    is_paid             = db.Column(db.Boolean, default=False)
    paid_at             = db.Column(db.DateTime, nullable=True)
    razorpay_payment_id = db.Column(db.String(100), nullable=True)
    created_at          = db.Column(db.DateTime, default=datetime.utcnow)
    last_breach_check   = db.Column(db.DateTime, nullable=True)
    known_breaches      = db.Column(db.Text, default='')
    scans               = db.relationship('ScanHistory', backref='user', lazy=True)
    api_key             = db.Column(db.String(64), unique=True, nullable=True)
    webhook_url         = db.Column(db.String(500), nullable=True)

    def is_admin(self):
        return self.role in ('owner', 'admin')


class ScanHistory(db.Model):
    id         = db.Column(db.Integer, primary_key=True)
    tenant_id  = db.Column(db.Integer, db.ForeignKey('tenant.id'), nullable=False)
    user_id    = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    scan_type  = db.Column(db.String(20))
    input_val  = db.Column(db.String(300))
    result     = db.Column(db.String(50))
    details    = db.Column(db.Text)
    scanned_at = db.Column(db.DateTime, default=datetime.utcnow)


class DomainMonitor(db.Model):
    """A company domain a tenant wants monitored as a whole (not just one
    person's email). Must be verified via DNS TXT record before any scan
    runs against it — see verify_domain_txt(). This stops a tenant from
    monitoring a domain it does not own."""
    id                  = db.Column(db.Integer, primary_key=True)
    tenant_id           = db.Column(db.Integer, db.ForeignKey('tenant.id'), nullable=False)
    domain              = db.Column(db.String(255), nullable=False)
    added_by_user_id    = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    verification_token  = db.Column(db.String(64), nullable=False)
    verified            = db.Column(db.Boolean, default=False)
    verified_at         = db.Column(db.DateTime, nullable=True)
    last_scanned_at     = db.Column(db.DateTime, nullable=True)
    created_at          = db.Column(db.DateTime, default=datetime.utcnow)

    __table_args__ = (db.UniqueConstraint('tenant_id', 'domain', name='uq_tenant_domain'),)


class CredentialFinding(db.Model):
    """One discovered exposure: a specific email turning up under a specific
    breach source. This is the unit that status states, confidence scores,
    and the exposure timeline are all built on top of.
    NOTE: this table intentionally has no password/credential-value column.
    We track and manage the *fact* of an exposure, never the leaked secret
    itself — see docs/ARCHITECTURE.md 'Why we don't store leaked passwords'."""
    id               = db.Column(db.Integer, primary_key=True)
    tenant_id        = db.Column(db.Integer, db.ForeignKey('tenant.id'), nullable=False)
    user_id          = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    domain_monitor_id = db.Column(db.Integer, db.ForeignKey('domain_monitor.id'), nullable=True)
    email            = db.Column(db.String(255), nullable=False)
    source_name      = db.Column(db.String(200), nullable=False)
    status           = db.Column(db.String(20), default=STATUS_ACTIVE)
    confidence_score = db.Column(db.Integer, default=50)   # 0-100
    sources_seen      = db.Column(db.Integer, default=1)    # how many providers confirmed this
    first_seen       = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen        = db.Column(db.DateTime, default=datetime.utcnow)
    status_changed_at = db.Column(db.DateTime, nullable=True)
    resolved_at      = db.Column(db.DateTime, nullable=True)

    __table_args__ = (db.UniqueConstraint('tenant_id', 'email', 'source_name', name='uq_tenant_email_source'),)


class AuditLog(db.Model):
    """Admin-visible record of who-did-what-when on this tenant's account.
    Distinct from ScanHistory: ScanHistory is 'what was scanned', AuditLog is
    'what administrative/state-changing action was taken'."""
    id            = db.Column(db.Integer, primary_key=True)
    tenant_id     = db.Column(db.Integer, db.ForeignKey('tenant.id'), nullable=False)
    actor_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    action        = db.Column(db.String(80), nullable=False)
    target        = db.Column(db.String(300), nullable=True)
    ip_address    = db.Column(db.String(64), nullable=True)
    meta          = db.Column(db.Text, nullable=True)  # JSON string
    created_at    = db.Column(db.DateTime, default=datetime.utcnow)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ─────────────────────────────────────────────────────────
# Audit logging
# ─────────────────────────────────────────────────────────
def log_audit(action, target=None, meta=None, actor=None):
    actor = actor or (current_user if getattr(current_user, 'is_authenticated', False) else None)
    entry = AuditLog(
        tenant_id=actor.tenant_id if actor else None,
        actor_user_id=actor.id if actor else None,
        action=action,
        target=target,
        ip_address=request.remote_addr if request else None,
        meta=json.dumps(meta) if meta else None
    )
    db.session.add(entry)
    db.session.commit()


def require_role(*roles):
    def wrapper(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if not current_user.is_authenticated or current_user.role not in roles:
                flash('You do not have permission to view that page.', 'error')
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated
    return wrapper


def send_email_brevo(to_email, subject, body):
    if not MAIL_FROM_ADDRESS:
        logger.error("send_email_brevo() called but MAIL_USERNAME is not set in the environment — email not sent.")
        return False
    try:
        configuration = sib_api_v3_sdk.Configuration()
        configuration.api_key['api-key'] = os.environ.get('BREVO_API_KEY')
        api_instance = sib_api_v3_sdk.TransactionalEmailsApi(
            sib_api_v3_sdk.ApiClient(configuration)
        )
        send_smtp_email = sib_api_v3_sdk.SendSmtpEmail(
            to=[{"email": to_email}],
            sender={"email": MAIL_FROM_ADDRESS, "name": "GhostLeaks"},
            subject=subject,
            text_content=body
        )
        api_instance.send_transac_email(send_smtp_email)
        return True
    except ApiException as e:
        logger.error(f"Brevo email send failed: {e}")
        return False


def send_verification_email(user):
    token = s.dumps(user.email, salt='email-verify')
    verify_url = url_for('verify_email', token=token, _external=True)
    body = f'''Confirm your GhostLeaks account

Hi {user.name},

Please confirm this is your email address by clicking the link below:
{verify_url}

This link expires in 24 hours. Until you confirm, this address will not
receive automated breach alerts — this stops anyone from registering an
email they don't own and getting alerts about it.

If you did not create this account, ignore this email.

— GhostLeaks
'''
    return send_email_brevo(user.email, 'Confirm your GhostLeaks account', body)


def check_password_hibp(password):
    """Uses HIBP's k-anonymity range API: only a 5-char SHA1 prefix ever
    leaves this server, so the real password is never transmitted or
    exposed to a third party. Returns (found: bool, times_seen: int)."""
    sha1 = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    try:
        response = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}", timeout=5)
        response.raise_for_status()
        for line in response.text.splitlines():
            h, count = line.split(':')
            if h == suffix:
                return True, int(count)
        return False, 0
    except:
        return None, 0


# ─────────────────────────────────────────────────────────
# Breach source providers
#
# SECURITY FIX (2026-07-22): providers must NEVER return a leaked
# credential's actual password/secret value to the caller. We only ever
# surface the FACT of exposure (which source, roughly when) — never the
# secret itself. This is what turns this from a credential-lookup tool
# into a breach-notification tool. See docs/ARCHITECTURE.md.
#
# REFACTOR (2026-07-24): provider-specific code has moved out of app.py
# and into providers/ (see providers/base_provider.py for the interface).
# This block just builds the active provider list from config — adding a
# new provider means writing one new providers/*.py module and adding one
# line to _build_active_providers(); nothing else in this file needs to
# change. Confidence scoring below still rewards findings confirmed by
# more than one provider — set BREACH_PROVIDER to a comma-separated list
# (e.g. "breachdirectory,hibp") to enable that.
# ─────────────────────────────────────────────────────────

from providers.breachdirectory import BreachDirectoryProvider
from providers.hibp import HIBPProvider
from providers.leakcheck import LeakCheckProvider
from providers.xposedornot import XposedOrNotProvider


def _build_active_providers():
    """Reads BREACH_PROVIDER (single name or comma-separated list) and
    returns the corresponding provider instances, each already configured
    with its API key from the environment."""
    factories = {
        'breachdirectory': lambda: BreachDirectoryProvider(RAPIDAPI_KEY),
        'hibp': lambda: HIBPProvider(HIBP_API_KEY),
        'leakcheck': lambda: LeakCheckProvider(LEAKCHECK_API_KEY),
        'xposedornot': lambda: XposedOrNotProvider(XPOSEDORNOT_API_KEY),
    }
    names = [n.strip().lower() for n in BREACH_PROVIDER.split(',') if n.strip()]
    active = []
    for name in names:
        factory = factories.get(name)
        if not factory:
            logger.warning(f"Unknown BREACH_PROVIDER '{name}' — skipping. Valid options: {list(factories)}")
            continue
        active.append(factory())
    return active


BREACH_PROVIDERS = _build_active_providers()


def aggregate_breach_sources(email):
    """Calls every configured provider and merges results by source name.
    Returns (sources, check_failed):
      sources      — list of {'source': name, 'confirmed_by': n}
      check_failed — True if EVERY configured provider failed to respond,
                     meaning we could not actually determine leaked/safe.
                     Callers must surface this distinctly — an empty
                     `sources` list with check_failed=True is NOT the same
                     as a clean scan result."""
    tally = {}
    any_ok = False
    for provider in BREACH_PROVIDERS:
        try:
            results, ok = provider.check_email(email)
        except Exception as e:
            logger.warning(f"Breach provider '{provider.name}' raised unexpectedly: {e}")
            results, ok = [], False
        if ok:
            any_ok = True
        for r in (results or []):
            name = r['source']
            tally[name] = tally.get(name, 0) + 1
    sources = [{'source': name, 'confirmed_by': count} for name, count in tally.items()]
    check_failed = not any_ok
    return sources, check_failed


def compute_confidence(confirmed_by, first_seen, last_seen):
    """0-100. Baseline per single-source hit is deliberately modest (60) —
    with only one provider configured today, that ceiling is honest; wire
    up a second provider (see BREACH_PROVIDERS) to let cross-confirmed
    findings earn the +40 bonus below."""
    score = 60
    if confirmed_by > 1:
        score += min((confirmed_by - 1) * 20, 40)
    days_exposed = (last_seen - first_seen).days if last_seen and first_seen else 0
    if days_exposed > 365:
        score += 5
    return max(0, min(100, score))


def upsert_finding(tenant_id, email, source_name, confirmed_by, user_id=None, domain_monitor_id=None):
    now = datetime.utcnow()
    finding = CredentialFinding.query.filter_by(
        tenant_id=tenant_id, email=email, source_name=source_name
    ).first()
    if finding:
        finding.last_seen = now
        finding.sources_seen = max(finding.sources_seen, confirmed_by)
        finding.confidence_score = compute_confidence(confirmed_by, finding.first_seen, now)
        if user_id and not finding.user_id:
            finding.user_id = user_id
        if domain_monitor_id and not finding.domain_monitor_id:
            finding.domain_monitor_id = domain_monitor_id
    else:
        finding = CredentialFinding(
            tenant_id=tenant_id, email=email, source_name=source_name,
            status=STATUS_ACTIVE, sources_seen=confirmed_by,
            confidence_score=compute_confidence(confirmed_by, now, now),
            first_seen=now, last_seen=now,
            user_id=user_id, domain_monitor_id=domain_monitor_id
        )
        db.session.add(finding)
    try:
        db.session.commit()
    except Exception:
        # Two concurrent scans raced to create the same (tenant, email,
        # source) row and both hit the unique constraint — back off and
        # use whichever row actually landed instead of erroring the request.
        db.session.rollback()
        finding = CredentialFinding.query.filter_by(
            tenant_id=tenant_id, email=email, source_name=source_name
        ).first()
    return finding


# ─────────────────────────────────────────────────────────
# Domain ownership verification (DNS TXT record)
# ─────────────────────────────────────────────────────────
def make_verification_token():
    return secrets.token_hex(16)


def verify_domain_txt(domain, token):
    """Checks for a TXT record at _ghostleaks-verify.<domain> containing
    'ghostleaks-verify=<token>'. This is what gates domain-wide monitoring
    — without it, a tenant could enumerate exposure data for a domain it
    doesn't control, which is exactly the kind of unverified bulk lookup
    this rebuild is meant to remove."""
    if not DNS_AVAILABLE:
        return False, 'dnspython is not installed on this server.'
    record_name = f"_ghostleaks-verify.{domain}"
    expected = f"ghostleaks-verify={token}"
    try:
        answers = dns.resolver.resolve(record_name, 'TXT', lifetime=8)
        for rdata in answers:
            txt_value = b''.join(rdata.strings).decode('utf-8', errors='ignore')
            if txt_value.strip() == expected:
                return True, 'ok'
        return False, 'TXT record found but value did not match.'
    except dns.resolver.NXDOMAIN:
        return False, 'No TXT record found at ' + record_name
    except dns.resolver.NoAnswer:
        return False, 'No TXT record found at ' + record_name
    except Exception as e:
        return False, f'DNS lookup failed: {e}'


# ─────────────────────────────────────────────────────────
# Executive Risk Score
# ─────────────────────────────────────────────────────────
def calculate_risk_score(user):
    all_scans = ScanHistory.query.filter_by(user_id=user.id).all()
    if not all_scans:
        return 100, 'Unknown'

    total_scans = len(all_scans)
    leaked_scans = [sc for sc in all_scans if sc.result == 'leaked']
    leaked_count = len(leaked_scans)

    score = 100
    breach_ratio = leaked_count / total_scans
    score -= int(breach_ratio * 40)

    distinct_sources = set()
    for sc in leaked_scans:
        if sc.details:
            distinct_sources.add(sc.details)
    score -= min(len(distinct_sources) * 5, 30)

    if leaked_scans:
        most_recent = max(leaked_scans, key=lambda sc: sc.scanned_at)
        days_ago = (datetime.utcnow() - most_recent.scanned_at).days
        if days_ago < 7:
            score -= 30
        elif days_ago < 30:
            score -= 20
        elif days_ago < 90:
            score -= 10

    score = max(0, min(100, score))

    if score >= 80:
        level = 'Low'
    elif score >= 60:
        level = 'Medium'
    elif score >= 40:
        level = 'High'
    else:
        level = 'Critical'

    return score, level


# ─────────────────────────────────────────────────────────
# REST API auth (X-API-Key header) + Webhook support
# ─────────────────────────────────────────────────────────
def generate_api_key():
    return 'gl_' + secrets.token_hex(24)


def require_api_key(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        key = request.headers.get('X-API-Key', '')
        if not key:
            return jsonify({'error': 'Missing X-API-Key header'}), 401
        user = User.query.filter_by(api_key=key).first()
        if not user:
            return jsonify({'error': 'Invalid API key'}), 401
        if not user.is_paid:
            return jsonify({'error': 'UPGRADE_REQUIRED'}), 402
        request.api_user = user
        return f(*args, **kwargs)
    return decorated


def is_safe_webhook_url(url):
    try:
        parsed = urlparse(url)
        if parsed.scheme != 'https':
            return False, 'Webhook URL must start with https://'
        hostname = parsed.hostname
        if not hostname:
            return False, 'Invalid webhook URL'
        addr_info = socket.getaddrinfo(hostname, None)
        for info in addr_info:
            ip = ipaddress.ip_address(info[4][0])
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
                return False, 'Webhook URL cannot point to a private or internal address'
        return True, 'ok'
    except socket.gaierror:
        return False, 'Could not resolve webhook hostname'
    except Exception:
        return False, 'Invalid webhook URL'


def send_webhook(user, event_type, payload):
    if not user.webhook_url:
        return
    # SECURITY: is_safe_webhook_url() was already checked once when the URL
    # was saved in /settings, but that is not enough on its own:
    #   1. DNS rebinding — the hostname can resolve to a public IP at save
    #      time and to a private/internal IP (e.g. cloud metadata) later,
    #      at send time.
    #   2. Redirects — requests follows redirects by default, so a webhook
    #      that starts on an allowed https:// host can 30x to an internal
    #      address and requests will happily follow it.
    # Re-validate immediately before every send, and disable redirects so
    # the destination that was checked is the destination actually hit.
    is_safe, reason = is_safe_webhook_url(user.webhook_url)
    if not is_safe:
        logger.warning(f"Webhook send blocked for user_id={user.id}: {reason}")
        return
    body = {
        'event': event_type,
        'user_email': user.email,
        'timestamp': datetime.utcnow().isoformat(),
        'data': payload
    }
    try:
        requests.post(user.webhook_url, json=body, timeout=5, allow_redirects=False)
    except Exception as e:
        logger.warning(f"Webhook delivery failed for user_id={user.id}: {e}")

# ─────────────────────────────────────────────────────────
# Tenant branding — injected into every template as `brand`
# ─────────────────────────────────────────────────────────
@app.context_processor
def inject_brand():
    public_url = APP_PUBLIC_URL or request.url_root.rstrip('/')
    if getattr(current_user, 'is_authenticated', False) and current_user.tenant:
        t = current_user.tenant
        return dict(brand={'name': t.brand_name, 'color': t.primary_color, 'logo': t.logo_url},
                    app_public_url=public_url)
    return dict(brand={'name': 'GhostLeaks', 'color': '#3ddc97', 'logo': None}, app_public_url=public_url)


@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('landing.html')


@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("10 per hour")
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        name         = request.form.get('name', '').strip()
        email        = request.form.get('email', '').strip().lower()
        password     = request.form.get('password', '')
        confirm      = request.form.get('confirm', '')
        company_name = request.form.get('company_name', '').strip()
        tenant_slug  = request.form.get('tenant_slug', '').strip().lower()

        if not name or not email or not password:
            flash('All fields are required.', 'error')
            return render_template('register.html')
        if password != confirm:
            flash('Passwords do not match.', 'error')
            return render_template('register.html')
        if len(password) < 8:
            flash('Password must be at least 8 characters.', 'error')
            return render_template('register.html')
        if User.query.filter_by(email=email).first():
            flash('Email already registered. Please login.', 'error')
            return render_template('register.html')

        # Multi-tenant onboarding: join an existing tenant by slug (invite
        # link), or spin up a brand new isolated tenant for this company.
        if tenant_slug:
            tenant = Tenant.query.filter_by(slug=tenant_slug).first()
            if not tenant:
                flash('That workspace invite link is invalid.', 'error')
                return render_template('register.html')
            role = 'member'
        else:
            base_slug = (company_name or name or 'workspace').lower().replace(' ', '-')[:60]
            slug = base_slug
            n = 1
            while Tenant.query.filter_by(slug=slug).first():
                n += 1
                slug = f"{base_slug}-{n}"
            tenant = Tenant(name=company_name or f"{name}'s Workspace", slug=slug)
            db.session.add(tenant)
            db.session.flush()  # get tenant.id before creating the user
            role = 'owner'

        hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')
        user = User(name=name, email=email, password=hashed_pw, api_key=generate_api_key(),
                    tenant_id=tenant.id, role=role)
        db.session.add(user)
        db.session.commit()
        login_user(user)
        log_audit('user_registered', target=email, meta={'tenant_id': tenant.id, 'role': role})
        sent = send_verification_email(user)
        if sent:
            flash(f'Welcome, {name}! Please check your inbox to confirm your email address.', 'success')
        else:
            flash(f'Welcome, {name}! We could not send a verification email right now — you can request one again from your dashboard.', 'error')
        return redirect(url_for('dashboard'))
    return render_template('register.html')


def is_safe_redirect_target(target):
    """Only allow redirecting to a local path (e.g. '/dashboard'), never to
    an absolute/external URL — prevents the login 'next' param being used
    for an open-redirect / phishing hop."""
    if not target:
        return False
    parsed = urlparse(target)
    return not parsed.netloc and not parsed.scheme and target.startswith('/')


@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per 5 minutes")
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        email    = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user, remember=True)
            log_audit('login_success', target=email, actor=user)
            next_page = request.args.get('next')
            if next_page and is_safe_redirect_target(next_page):
                return redirect(next_page)
            return redirect(url_for('dashboard'))
        flash('Invalid email or password.', 'error')
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    log_audit('logout', target=current_user.email)
    logout_user()
    return redirect(url_for('login'))


@app.route('/forgot-password', methods=['GET', 'POST'])
@limiter.limit("5 per hour")
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        user = User.query.filter_by(email=email).first()
        if user:
            token = s.dumps(email, salt='password-reset')
            reset_url = url_for('reset_password', token=token, _external=True)
            body = f'''GhostLeaks Password Reset

Click the link below to reset your password:
{reset_url}

This link expires in 30 minutes.

If you did not request this, ignore this email.

— GhostLeaks
'''
            success = send_email_brevo(email, 'GhostLeaks — Password Reset', body)
            if success:
                flash('Reset link sent! Check your email.', 'success')
            else:
                flash('Email send failed. Try again.', 'error')
        else:
            flash('If that email exists, a reset link has been sent.', 'success')
        return redirect(url_for('login'))
    return render_template('forgot_password.html')


@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = s.loads(token, salt='password-reset', max_age=1800)
    except:
        flash('Reset link is invalid or expired.', 'error')
        return redirect(url_for('forgot_password'))
    if request.method == 'POST':
        password = request.form.get('password', '')
        confirm  = request.form.get('confirm', '')
        if len(password) < 8:
            flash('Password must be at least 8 characters.', 'error')
            return render_template('reset_password.html', token=token)
        if password != confirm:
            flash('Passwords do not match.', 'error')
            return render_template('reset_password.html', token=token)
        user = User.query.filter_by(email=email).first()
        if user:
            user.password = bcrypt.generate_password_hash(password).decode('utf-8')
            db.session.commit()
            log_audit('password_reset', target=email, actor=user)
            flash('Password reset successful! Please login.', 'success')
            return redirect(url_for('login'))
    return render_template('reset_password.html', token=token)


@app.route('/verify-email/<token>')
def verify_email(token):
    try:
        email = s.loads(token, salt='email-verify', max_age=86400)  # 24 hours
    except Exception:
        flash('That verification link is invalid or has expired. Request a new one from Settings.', 'error')
        return redirect(url_for('login'))
    user = User.query.filter_by(email=email).first()
    if not user:
        flash('That verification link is invalid.', 'error')
        return redirect(url_for('login'))
    if not user.email_verified:
        user.email_verified = True
        db.session.commit()
        log_audit('email_verified', target=email, actor=user)
    flash('Email confirmed — you will now receive breach alerts at this address.', 'success')
    return redirect(url_for('dashboard') if current_user.is_authenticated else url_for('login'))


@app.route('/resend-verification', methods=['POST'])
@login_required
@limiter.limit("5 per hour")
def resend_verification():
    if current_user.email_verified:
        flash('Your email is already verified.', 'success')
    else:
        send_verification_email(current_user)
        flash('Verification email sent — check your inbox.', 'success')
    return redirect(url_for('dashboard'))

@app.route('/dashboard')
@login_required
def dashboard():
    recent_scans = ScanHistory.query.filter_by(user_id=current_user.id)\
                    .order_by(ScanHistory.scanned_at.desc()).limit(10).all()
    total_scans  = ScanHistory.query.filter_by(user_id=current_user.id).count()
    leaked_scans = ScanHistory.query.filter_by(user_id=current_user.id, result='leaked').count()
    risk_score, risk_level = calculate_risk_score(current_user)
    open_findings = CredentialFinding.query.filter_by(
        tenant_id=current_user.tenant_id, user_id=current_user.id
    ).filter(CredentialFinding.status.in_([STATUS_ACTIVE])).count()
    domains = DomainMonitor.query.filter_by(tenant_id=current_user.tenant_id).all()
    return render_template('dashboard.html',
        recent_scans=recent_scans,
        total_scans=total_scans,
        leaked_scans=leaked_scans,
        risk_score=risk_score,
        risk_level=risk_level,
        open_findings=open_findings,
        domains=domains,
        valid_statuses=VALID_STATUSES)


@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    if request.method == 'POST':
        webhook_url = request.form.get('webhook_url', '').strip()
        if webhook_url:
            is_safe, reason = is_safe_webhook_url(webhook_url)
            if not is_safe:
                flash(f'Webhook URL rejected: {reason}', 'error')
                return render_template('settings.html')
            current_user.webhook_url = webhook_url
        else:
            current_user.webhook_url = None
        db.session.commit()
        log_audit('settings_updated', target=current_user.email)
        flash('Settings saved successfully.', 'success')
        return redirect(url_for('dashboard'))
    if not current_user.api_key:
        current_user.api_key = generate_api_key()
        db.session.commit()
    return render_template('settings.html')


@app.route('/settings/regenerate-api-key', methods=['POST'])
@login_required
def regenerate_api_key():
    current_user.api_key = generate_api_key()
    db.session.commit()
    log_audit('api_key_regenerated', target=current_user.email)
    flash('API key regenerated. Update any integrations using the old key.', 'success')
    return redirect(url_for('settings'))


@app.route('/check-password', methods=['POST'])
@login_required
@limiter.limit("30 per minute")
def check_pwd():
    data = request.get_json()
    password = data.get('password', '')
    if not password:
        return jsonify({'error': 'Empty password'})
    found, count = check_password_hibp(password)
    history = ScanHistory(
        tenant_id=current_user.tenant_id,
        user_id=current_user.id,
        scan_type='password',
        input_val='*' * len(password),
        result='leaked' if found else 'safe',
        details=f"Found {count} times" if found else "Not found"
    )
    db.session.add(history)
    db.session.commit()
    return jsonify({'found': found, 'count': count})


@app.route('/check-email', methods=['POST'])
@login_required
@limiter.limit("30 per minute")
def check_email():
    if not current_user.is_paid:
        return jsonify({'error': 'UPGRADE_REQUIRED'})
    data = request.get_json()
    email = data.get('email', '')
    if not email:
        return jsonify({'error': 'Empty email'})
    if not RAPIDAPI_KEY:
        return jsonify({'error': 'Breach checking is not configured on this server. Contact the administrator.'})

    sources, check_failed = aggregate_breach_sources(email)
    if check_failed:
        history = ScanHistory(
            tenant_id=current_user.tenant_id, user_id=current_user.id, scan_type='email',
            input_val=email, result='check_failed',
            details="Breach data provider was unreachable — result is NOT a confirmed safe status"
        )
        db.session.add(history)
        db.session.commit()
        return jsonify({'error': 'CHECK_FAILED',
                         'message': 'The breach-data provider did not respond. This is not a confirmed safe result — please try again shortly.'}), 502

    findings = []
    for s_ in sources:
        f = upsert_finding(current_user.tenant_id, email, s_['source'], s_['confirmed_by'], user_id=current_user.id)
        findings.append(f)

    history = ScanHistory(
        tenant_id=current_user.tenant_id,
        user_id=current_user.id,
        scan_type='email',
        input_val=email,
        result='leaked' if sources else 'safe',
        details=f"{len(sources)} breaches found" if sources else "Not found"
    )
    db.session.add(history)
    db.session.commit()

    if findings:
        send_webhook(current_user, 'breach_detected', {
            'email': email,
            'breach_count': len(findings),
            'sources': [f.source_name for f in findings]
        })

    # NOTE: response contains source name, confidence, and status only —
    # never a password/credential value.
    return jsonify({'breaches': [
        {'name': f.source_name, 'confidence_score': f.confidence_score,
         'status': f.status, 'finding_id': f.id} for f in findings
    ]})


@app.route('/findings/<int:finding_id>/status', methods=['POST'])
@login_required
def update_finding_status(finding_id):
    finding = CredentialFinding.query.filter_by(id=finding_id, tenant_id=current_user.tenant_id).first()
    if not finding:
        return jsonify({'error': 'Not found'}), 404
    # Owner of the finding, or a tenant admin/owner, may change its status.
    if finding.user_id != current_user.id and not current_user.is_admin():
        return jsonify({'error': 'Not permitted'}), 403
    data = request.get_json(silent=True) or {}
    new_status = data.get('status', '')
    if new_status not in VALID_STATUSES:
        return jsonify({'error': f'Invalid status. Must be one of {VALID_STATUSES}'}), 400
    old_status = finding.status
    finding.status = new_status
    finding.status_changed_at = datetime.utcnow()
    if new_status == STATUS_RESOLVED:
        finding.resolved_at = datetime.utcnow()
    db.session.commit()
    log_audit('finding_status_change', target=f"{finding.email} / {finding.source_name}",
              meta={'from': old_status, 'to': new_status, 'finding_id': finding.id})
    return jsonify({'ok': True, 'finding_id': finding.id, 'status': new_status})


@app.route('/findings')
@login_required
def list_findings():
    q = CredentialFinding.query.filter_by(tenant_id=current_user.tenant_id)
    if not current_user.is_admin():
        q = q.filter_by(user_id=current_user.id)
    status_filter = request.args.get('status')
    if status_filter in VALID_STATUSES:
        q = q.filter_by(status=status_filter)
    findings = q.order_by(CredentialFinding.last_seen.desc()).all()
    return render_template('findings.html', findings=findings, valid_statuses=VALID_STATUSES,
                            active_filter=status_filter)

@app.route('/bulk-check', methods=['POST'])
@login_required
@limiter.limit("3 per hour")
def bulk_check():
    if not current_user.is_paid:
        return jsonify({'error': 'UPGRADE_REQUIRED'})
    if not RAPIDAPI_KEY:
        return jsonify({'error': 'Breach checking is not configured on this server. Contact the administrator.'})
    today_bulk = ScanHistory.query.filter_by(
        user_id=current_user.id,
        scan_type='bulk'
    ).filter(
        db.func.date(ScanHistory.scanned_at) == date.today()
    ).count()
    if today_bulk >= 3:
        return jsonify({'error': 'Daily limit reached. Maximum 3 bulk scans per day.'})
    if 'csv_file' not in request.files:
        return jsonify({'error': 'No file uploaded'})
    file = request.files['csv_file']
    file.stream.seek(0, os.SEEK_END)
    file_size = file.stream.tell()
    file.stream.seek(0)
    MAX_CSV_BYTES = 1 * 1024 * 1024  # 1 MB
    if file_size > MAX_CSV_BYTES:
        return jsonify({'error': f'CSV file too large ({file_size // 1024} KB). Max size is 1 MB.'}), 400
    try:
        content = file.stream.read().decode("UTF-8")
    except UnicodeDecodeError:
        return jsonify({'error': 'CSV file must be UTF-8 text.'}), 400
    emails = []
    for line in content.splitlines():
        email = line.strip().strip('"').strip("'")
        if email and '@' in email:
            emails.append(email)
    emails = emails[:100]
    if not emails:
        return jsonify({'error': 'No valid emails found in CSV'})
    results = []
    leaked_count = 0
    safe_count = 0
    failed_count = 0
    for email in emails:
        sources, check_failed = aggregate_breach_sources(email)
        if check_failed:
            failed_count += 1
            results.append({'email': email, 'status': 'check_failed', 'breach_count': 0, 'breaches': []})
            continue
        for s_ in sources:
            upsert_finding(current_user.tenant_id, email, s_['source'], s_['confirmed_by'], user_id=current_user.id)
        is_leaked = len(sources) > 0
        if is_leaked:
            leaked_count += 1
        else:
            safe_count += 1
        results.append({
            'email': email,
            'status': 'leaked' if is_leaked else 'safe',
            'breach_count': len(sources),
            'breaches': [s_['source'] for s_ in sources]
        })
    history = ScanHistory(
        tenant_id=current_user.tenant_id,
        user_id=current_user.id,
        scan_type='bulk',
        input_val=f"{len(emails)} emails",
        result=f"{leaked_count} leaked / {safe_count} safe / {failed_count} check failed",
        details=f"Bulk scan of {len(emails)} emails"
    )
    db.session.add(history)
    db.session.commit()
    return jsonify({'total': len(emails), 'leaked': leaked_count, 'safe': safe_count,
                     'check_failed': failed_count, 'results': results})


@app.route('/api/risk-score')
@login_required
def api_risk_score():
    score, level = calculate_risk_score(current_user)
    return jsonify({'risk_score': score, 'risk_level': level})


# ─────────────────────────────────────────────────────────
# Domain monitoring
# ─────────────────────────────────────────────────────────
@app.route('/domains', methods=['POST'])
@login_required
def add_domain():
    if not current_user.is_admin():
        return jsonify({'error': 'Only workspace admins can add a monitored domain'}), 403
    domain = (request.form.get('domain') or (request.get_json(silent=True) or {}).get('domain', '')).strip().lower()
    if not domain or '.' not in domain:
        flash('Enter a valid domain, e.g. example.com', 'error')
        return redirect(url_for('dashboard'))
    existing = DomainMonitor.query.filter_by(tenant_id=current_user.tenant_id, domain=domain).first()
    if existing:
        flash('That domain is already being tracked.', 'error')
        return redirect(url_for('dashboard'))
    dm = DomainMonitor(
        tenant_id=current_user.tenant_id, domain=domain,
        added_by_user_id=current_user.id,
        verification_token=make_verification_token()
    )
    db.session.add(dm)
    db.session.commit()
    log_audit('domain_added', target=domain, meta={'domain_id': dm.id})
    flash(f'Domain added. Add the DNS TXT record shown below to verify ownership of {domain}.', 'success')
    return redirect(url_for('dashboard'))


@app.route('/domains/<int:domain_id>/verify', methods=['POST'])
@login_required
def verify_domain(domain_id):
    dm = DomainMonitor.query.filter_by(id=domain_id, tenant_id=current_user.tenant_id).first()
    if not dm:
        return jsonify({'error': 'Not found'}), 404
    if not current_user.is_admin():
        return jsonify({'error': 'Not permitted'}), 403
    ok, reason = verify_domain_txt(dm.domain, dm.verification_token)
    if ok:
        dm.verified = True
        dm.verified_at = datetime.utcnow()
        db.session.commit()
        log_audit('domain_verified', target=dm.domain, meta={'domain_id': dm.id})
        flash(f'{dm.domain} is now verified.', 'success')
    else:
        flash(f'Verification failed: {reason}', 'error')
    return redirect(url_for('dashboard'))


@app.route('/domains/<int:domain_id>/scan', methods=['POST'])
@login_required
@limiter.limit("10 per hour")
def scan_domain(domain_id):
    dm = DomainMonitor.query.filter_by(id=domain_id, tenant_id=current_user.tenant_id).first()
    if not dm:
        return jsonify({'error': 'Not found'}), 404
    if not current_user.is_admin():
        return jsonify({'error': 'Not permitted'}), 403
    if not dm.verified:
        flash('Verify domain ownership before scanning.', 'error')
        return redirect(url_for('dashboard'))
    if not RAPIDAPI_KEY:
        flash('Breach checking is not configured on this server.', 'error')
        return redirect(url_for('dashboard'))

    # IMPORTANT LIMITATION (see docs/ARCHITECTURE.md "Domain monitoring
    # honesty note"): BreachDirectory's public API is an email/username
    # lookup, not a true domain-wide search. Until a provider with real
    # domain-level discovery is configured, this checks the domain itself
    # as a search term as a best-effort pass — it will often return
    # little or nothing for a domain that has no directly-indexed record.
    sources, check_failed = aggregate_breach_sources(dm.domain)
    if check_failed:
        flash(f'Scan could not complete — the breach data provider did not respond. This is not a confirmed clean result; try again shortly.', 'error')
        return redirect(url_for('dashboard'))
    for s_ in sources:
        upsert_finding(dm.tenant_id, dm.domain, s_['source'], s_['confirmed_by'], domain_monitor_id=dm.id)
    dm.last_scanned_at = datetime.utcnow()
    db.session.commit()
    log_audit('domain_scanned', target=dm.domain, meta={'findings': len(sources)})
    flash(f'Scan complete: {len(sources)} source(s) found for {dm.domain}.', 'success')
    return redirect(url_for('dashboard'))

# ─────────────────────────────────────────────────────────
# Exposure timeline
# ─────────────────────────────────────────────────────────
@app.route('/timeline')
@login_required
def timeline_page():
    return render_template('timeline.html')


@app.route('/api/timeline')
@login_required
def api_timeline():
    q = CredentialFinding.query.filter_by(tenant_id=current_user.tenant_id)
    if not current_user.is_admin():
        q = q.filter_by(user_id=current_user.id)
    findings = q.all()

    events = []
    for f in findings:
        events.append({
            'date': f.first_seen.isoformat(),
            'type': 'discovered',
            'email': f.email,
            'source': f.source_name,
            'confidence': f.confidence_score,
        })
        if f.status_changed_at:
            events.append({
                'date': f.status_changed_at.isoformat(),
                'type': 'status_change',
                'email': f.email,
                'source': f.source_name,
                'status': f.status,
            })
    events.sort(key=lambda e: e['date'], reverse=True)
    return jsonify({'events': events})


# ─────────────────────────────────────────────────────────
# Admin: audit logs + tenant branding settings
# ─────────────────────────────────────────────────────────
@app.route('/admin/audit-logs')
@login_required
@require_role('owner', 'admin')
def admin_audit_logs():
    logs = AuditLog.query.filter_by(tenant_id=current_user.tenant_id)\
            .order_by(AuditLog.created_at.desc()).limit(200).all()
    return render_template('admin_audit.html', logs=logs)


@app.route('/admin/tenant-settings', methods=['GET', 'POST'])
@login_required
@require_role('owner')
def admin_tenant_settings():
    tenant = current_user.tenant
    if request.method == 'POST':
        tenant.brand_name = request.form.get('brand_name', tenant.brand_name).strip() or tenant.brand_name
        color = request.form.get('primary_color', tenant.primary_color).strip()
        if color.startswith('#') and len(color) == 7:
            tenant.primary_color = color
        logo_url = request.form.get('logo_url', '').strip()
        tenant.logo_url = logo_url or None
        db.session.commit()
        log_audit('tenant_branding_updated', target=tenant.slug)
        flash('Branding updated.', 'success')
        return redirect(url_for('admin_tenant_settings'))
    members = User.query.filter_by(tenant_id=tenant.id).all()
    return render_template('admin_tenant.html', tenant=tenant, members=members)


@app.route('/pricing')
def pricing():
    return render_template('pricing.html', razorpay_key=RAZORPAY_KEY_ID, plan_amount=PLAN_AMOUNT)


@app.route('/create-order', methods=['POST'])
@login_required
def create_order():
    client = razorpay.Client(auth=(RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET))
    order = client.order.create({
        'amount': PLAN_AMOUNT,
        'currency': 'INR',
        'payment_capture': 1
    })
    return jsonify(order)


@app.route('/verify-payment', methods=['POST'])
@login_required
def verify_payment():
    data = request.get_json()
    client = razorpay.Client(auth=(RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET))
    try:
        client.utility.verify_payment_signature({
            'razorpay_order_id': data.get('razorpay_order_id'),
            'razorpay_payment_id': data.get('razorpay_payment_id'),
            'razorpay_signature': data.get('razorpay_signature')
        })
        current_user.is_paid = True
        current_user.paid_at = datetime.utcnow()
        current_user.razorpay_payment_id = data.get('razorpay_payment_id')
        db.session.commit()
        log_audit('payment_verified', target=current_user.email)
        return jsonify({'status': 'success'})
    except Exception as e:
        return jsonify({'status': 'failed', 'error': str(e)}), 400

@app.route('/api/v1/check-email', methods=['POST'])
@csrf.exempt
@require_api_key
@limiter.limit("60 per minute")
def api_v1_check_email():
    user = request.api_user
    data = request.get_json(silent=True) or {}
    email = data.get('email', '')
    if not email:
        return jsonify({'error': 'email field is required'}), 400
    if not RAPIDAPI_KEY:
        return jsonify({'error': 'Breach checking is not configured on this server. Contact the administrator.'}), 400

    sources, check_failed = aggregate_breach_sources(email)
    if check_failed:
        return jsonify({'error': 'CHECK_FAILED',
                         'message': 'The breach-data provider did not respond. This is not a confirmed safe result.'}), 502

    findings = [upsert_finding(user.tenant_id, email, s_['source'], s_['confirmed_by'], user_id=user.id)
                for s_ in sources]

    history = ScanHistory(
        tenant_id=user.tenant_id, user_id=user.id, scan_type='email', input_val=email,
        result='leaked' if sources else 'safe',
        details=f"{len(sources)} breaches found" if sources else "Not found"
    )
    db.session.add(history)
    db.session.commit()

    if findings:
        send_webhook(user, 'breach_detected', {
            'email': email, 'breach_count': len(findings),
            'sources': [f.source_name for f in findings]
        })

    return jsonify({
        'email': email,
        'leaked': len(findings) > 0,
        'breach_count': len(findings),
        # source, confidence, and status only — never a credential value
        'breaches': [{'name': f.source_name, 'confidence_score': f.confidence_score,
                      'status': f.status, 'finding_id': f.id} for f in findings]
    })


@app.route('/api/v1/check-password', methods=['POST'])
@csrf.exempt
@require_api_key
@limiter.limit("60 per minute")
def api_v1_check_password():
    user = request.api_user
    data = request.get_json(silent=True) or {}
    password = data.get('password', '')
    if not password:
        return jsonify({'error': 'password field is required'}), 400

    found, count = check_password_hibp(password)
    history = ScanHistory(
        tenant_id=user.tenant_id, user_id=user.id, scan_type='password',
        input_val='*' * len(password),
        result='leaked' if found else 'safe',
        details=f"Found {count} times" if found else "Not found"
    )
    db.session.add(history)
    db.session.commit()

    return jsonify({'leaked': bool(found), 'times_seen': count})


@app.route('/api/v1/risk-score', methods=['GET'])
@require_api_key
@limiter.limit("60 per minute")
def api_v1_risk_score():
    user = request.api_user
    score, level = calculate_risk_score(user)
    return jsonify({
        'email': user.email,
        'risk_score': score,
        'risk_level': level,
        'calculated_at': datetime.utcnow().isoformat()
    })


@app.route('/send-breach-alerts')
def send_breach_alerts():
    # Header-based, not a ?secret=... query param — query params get written
    # to server access logs, browser history, and any proxy in front of this
    # app, which would leak the shared secret. A custom header does not.
    provided_secret = request.headers.get('X-Alert-Secret', '')
    expected_secret = os.environ.get('ALERT_SECRET', '')
    if not expected_secret or provided_secret != expected_secret:
        return jsonify({'error': 'Unauthorized'}), 401

    # Only verified addresses — otherwise someone could register an email
    # they don't own and receive alerts confirming its exposure status.
    users = User.query.filter(User.is_paid == True, User.email_verified == True).all()
    sent = 0
    for user in users:
        try:
            sources, check_failed = aggregate_breach_sources(user.email)
            if check_failed:
                logger.warning(f"Skipping scheduled check for user_id={user.id} — breach provider unreachable.")
                continue
            if not sources:
                continue
            breach_names = ','.join([s_['source'] for s_ in sources])
            known = user.known_breaches or ''
            new_sources = [s_ for s_ in sources if s_['source'] not in known]
            if not new_sources:
                continue

            for s_ in new_sources:
                upsert_finding(user.tenant_id, user.email, s_['source'], s_['confirmed_by'], user_id=user.id)

            new_names = ', '.join([s_['source'] for s_ in new_sources])
            body = f'''GhostLeaks — New Exposure Detected

Hello {user.name},

Your email ({user.email}) was found in new data breach source(s):

{new_names}

Recommended next steps:
1. Change your password on the affected platform(s)
2. Enable two-factor authentication
3. Check whether the same password is reused elsewhere
4. Review and update the status of this finding in your GhostLeaks dashboard

— GhostLeaks
{APP_PUBLIC_URL or request.url_root.rstrip('/')}
'''
            success = send_email_brevo(user.email, 'GhostLeaks — New Exposure Detected', body)
            if success:
                user.known_breaches = breach_names
                user.last_breach_check = datetime.utcnow()
                db.session.commit()
                sent += 1

            send_webhook(user, 'breach_detected', {
                'source': 'scheduled_check',
                'new_breaches': [s_['source'] for s_ in new_sources]
            })
            time.sleep(0.5)
        except Exception as e:
            logger.error(f"Scheduled breach alert failed for user_id={user.id}: {e}")
            continue

    return jsonify({'status': 'done', 'alerts_sent': sent, 'total_users_checked': len(users)})

@app.route('/download-report', methods=['POST'])
@login_required
def download_report():
    if not current_user.is_paid:
        return jsonify({'error': 'UPGRADE_REQUIRED'})
    data = request.get_json()
    report_type = data.get('type', 'email')
    scan_data   = data.get('data', {})
    tenant = current_user.tenant

    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4,
        rightMargin=20*mm, leftMargin=20*mm, topMargin=20*mm, bottomMargin=20*mm)

    ACCENT = colors.HexColor(tenant.primary_color if tenant and tenant.primary_color else '#3ddc97')
    GRAY   = colors.HexColor('#888888')
    DANGER = colors.HexColor('#ff4d5e')
    WHITE  = colors.white
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle('title', fontSize=20, textColor=ACCENT,
        spaceAfter=4, fontName='Helvetica-Bold', alignment=TA_CENTER)
    sub_style = ParagraphStyle('sub', fontSize=9, textColor=GRAY,
        spaceAfter=2, fontName='Helvetica', alignment=TA_CENTER)
    heading_style = ParagraphStyle('heading', fontSize=12, textColor=ACCENT,
        spaceBefore=10, spaceAfter=6, fontName='Helvetica-Bold')
    body_style = ParagraphStyle('body', fontSize=9, textColor=colors.HexColor('#cccccc'),
        spaceAfter=4, fontName='Helvetica', leading=14)

    # SECURITY: everything below is inserted into ReportLab Paragraph markup,
    # which parses a restricted XML/HTML-like syntax and — critically — will
    # actually fetch the target of an <img src="..."/> tag when rendering.
    # scan_data comes straight from the request body, so any user-supplied
    # string (email, breach/source name, status) must be XML-escaped before
    # it touches a Paragraph, or a crafted value becomes a stored-markup /
    # server-side-request-forgery vector. Never interpolate raw external
    # input into Paragraph text.
    brand_name = xml_escape(tenant.brand_name if tenant and tenant.brand_name else 'GhostLeaks')
    elements = []
    elements.append(Paragraph(brand_name.upper(), title_style))
    elements.append(Paragraph("Credential Exposure Report", sub_style))
    elements.append(Paragraph(f"Generated: {datetime.utcnow().strftime('%d %B %Y, %H:%M UTC')}", sub_style))
    elements.append(Paragraph(f"User: {xml_escape(current_user.email)}", sub_style))
    elements.append(Spacer(1, 6*mm))
    elements.append(HRFlowable(width="100%", thickness=1, color=ACCENT))
    elements.append(Spacer(1, 4*mm))

    if report_type == 'email':
        email    = scan_data.get('email', '')
        breaches = scan_data.get('breaches', [])
        is_safe  = len(breaches) == 0
        elements.append(Paragraph("EMAIL EXPOSURE REPORT", heading_style))
        elements.append(Paragraph(f"Email Scanned: <b>{xml_escape(str(email))}</b>", body_style))
        elements.append(Paragraph(
            f"Status: <b>{'No exposures found' if is_safe else f'Found in {len(breaches)} source(s)'}</b>",
            body_style))
        elements.append(Spacer(1, 4*mm))
        if not is_safe:
            elements.append(Paragraph("EXPOSURE DETAILS", heading_style))
            table_data = [['#', 'Source', 'Status', 'Confidence']]
            for i, b in enumerate(breaches, 1):
                table_data.append([str(i), xml_escape(str(b.get('name', 'Unknown'))),
                                    xml_escape(str(b.get('status', 'active'))), f"{b.get('confidence_score', '-')}%"])
            t = Table(table_data, colWidths=[12*mm, 90*mm, 30*mm, 28*mm])
            t.setStyle(TableStyle([
                ('BACKGROUND',  (0,0), (-1,0), ACCENT),
                ('TEXTCOLOR',   (0,0), (-1,0), colors.black),
                ('FONTNAME',    (0,0), (-1,0), 'Helvetica-Bold'),
                ('FONTSIZE',    (0,0), (-1,-1), 8),
                ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.HexColor('#111111'), colors.HexColor('#0d0d0d')]),
                ('TEXTCOLOR',   (0,1), (-1,-1), colors.HexColor('#cccccc')),
                ('GRID',        (0,0), (-1,-1), 0.5, colors.HexColor('#2a2a2a')),
                ('PADDING',     (0,0), (-1,-1), 5),
            ]))
            elements.append(t)
    elif report_type == 'bulk':
        results      = scan_data.get('results', [])
        total        = scan_data.get('total', 0)
        leaked_count = scan_data.get('leaked', 0)
        safe_count   = scan_data.get('safe', 0)
        elements.append(Paragraph("BULK EXPOSURE REPORT", heading_style))
        summary_data = [['Total Emails', 'Leaked', 'Safe'], [str(total), str(leaked_count), str(safe_count)]]
        st = Table(summary_data, colWidths=[51*mm, 51*mm, 51*mm])
        st.setStyle(TableStyle([
            ('BACKGROUND',  (0,0), (-1,0), colors.HexColor('#1a1a1a')),
            ('TEXTCOLOR',   (0,0), (-1,0), GRAY),
            ('FONTNAME',    (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE',    (0,0), (-1,-1), 10),
            ('TEXTCOLOR',   (1,1), (1,1), DANGER),
            ('TEXTCOLOR',   (2,1), (2,1), ACCENT),
            ('TEXTCOLOR',   (0,1), (0,1), WHITE),
            ('FONTNAME',    (0,1), (-1,1), 'Helvetica-Bold'),
            ('ALIGN',       (0,0), (-1,-1), 'CENTER'),
            ('GRID',        (0,0), (-1,-1), 0.5, colors.HexColor('#2a2a2a')),
            ('PADDING',     (0,0), (-1,-1), 8),
        ]))
        elements.append(st)
        elements.append(Spacer(1, 5*mm))
        elements.append(Paragraph("DETAILED RESULTS", heading_style))
        table_data = [['#', 'Email', 'Status', 'Breaches', 'Sources']]
        for i, r in enumerate(results, 1):
            table_data.append([
                str(i), xml_escape(str(r.get('email', ''))), xml_escape(str(r.get('status', ''))),
                str(r.get('breach_count', 0)),
                xml_escape(', '.join(str(x) for x in r.get('breaches', []))) if r.get('breaches') else '-'
            ])
        t = Table(table_data, colWidths=[10*mm, 55*mm, 20*mm, 22*mm, 50*mm])
        t.setStyle(TableStyle([
            ('BACKGROUND',  (0,0), (-1,0), ACCENT),
            ('TEXTCOLOR',   (0,0), (-1,0), colors.black),
            ('FONTNAME',    (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE',    (0,0), (-1,-1), 7),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.HexColor('#111111'), colors.HexColor('#0d0d0d')]),
            ('TEXTCOLOR',   (0,1), (-1,-1), colors.HexColor('#cccccc')),
            ('GRID',        (0,0), (-1,-1), 0.5, colors.HexColor('#2a2a2a')),
            ('PADDING',     (0,0), (-1,-1), 4),
        ]))
        elements.append(t)

    elements.append(Spacer(1, 8*mm))
    elements.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor('#2a2a2a')))
    elements.append(Spacer(1, 3*mm))
    footer_url = APP_PUBLIC_URL or request.url_root.rstrip('/')
    elements.append(Paragraph(
        f"Generated by {brand_name} — {footer_url}",
        ParagraphStyle('footer', fontSize=7, textColor=colors.HexColor('#333333'),
            fontName='Helvetica', alignment=TA_CENTER)))
    doc.build(elements)
    buffer.seek(0)
    filename = f"exposure_report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.pdf"
    return send_file(buffer, mimetype='application/pdf', as_attachment=True, download_name=filename)


@app.errorhandler(413)
def request_too_large(e):
    return jsonify({'error': 'Upload too large. Maximum request size is 2 MB.'}), 413


with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
