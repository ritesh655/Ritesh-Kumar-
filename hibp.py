"""
Have I Been Pwned provider.

Uses HIBP's "breached account" API (requires a paid HIBP API key —
separate from the free k-anonymity password-range API app.py already
uses directly for check_password_hibp(), which is untouched by this
refactor).

NOTE: verify the response shape against HIBP's current API docs
(https://haveibeenpwned.com/API/v3) before relying on this in
production — third-party API contracts can change.
"""

import logging
import requests

from .base_provider import BaseProvider

logger = logging.getLogger(__name__)


class HIBPProvider(BaseProvider):
    name = "HIBP"

    def __init__(self, api_key):
        self.api_key = api_key

    def check_email(self, email):
        if not self.api_key:
            return [], False
        try:
            url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
            headers = {
                "hibp-api-key": self.api_key,
                "user-agent": "GhostLeaks",
            }
            response = requests.get(url, headers=headers, params={"truncateResponse": "true"}, timeout=10)
            if response.status_code == 404:
                # HIBP's documented way of saying "no breaches found" —
                # a real, successful check, not a failure.
                return [], True
            if response.status_code != 200:
                logger.warning(f"HIBP provider returned HTTP {response.status_code}")
                return [], False
            result = response.json()
        except Exception as e:
            logger.warning(f"HIBP provider call failed: {e}")
            return [], False

        out = []
        seen_names = set()
        for item in (result or []):
            name = item.get('Name') or item.get('name')
            if not name or name in seen_names:
                continue
            seen_names.add(name)
            out.append({'source': name})
        return out, True
