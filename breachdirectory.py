"""
BreachDirectory provider (via RapidAPI).

This is a direct port of the original inline provider_breachdirectory()
function that used to live in app.py — logic and behavior are unchanged,
it's just moved behind the BaseProvider interface.
"""

import logging
import requests

from .base_provider import BaseProvider

logger = logging.getLogger(__name__)


class BreachDirectoryProvider(BaseProvider):
    name = "BreachDirectory"

    def __init__(self, api_key):
        self.api_key = api_key

    def check_email(self, email):
        """Returns (matches, ok). ok=False means the provider call itself
        failed (network error, timeout, non-2xx, malformed response) —
        that is NOT the same as "checked successfully and found
        nothing"; callers must not silently treat a failed check as a
        safe result."""
        if not self.api_key:
            return [], False
        try:
            url = "https://breachdirectory.p.rapidapi.com/"
            headers = {
                "X-RapidAPI-Key": self.api_key,
                "X-RapidAPI-Host": "breachdirectory.p.rapidapi.com",
            }
            params = {"func": "auto", "term": email}
            response = requests.get(url, headers=headers, params=params, timeout=10)
            if response.status_code != 200:
                logger.warning(f"BreachDirectory provider returned HTTP {response.status_code}")
                return [], False
            result = response.json()
        except Exception as e:
            logger.warning(f"BreachDirectory provider call failed: {e}")
            return [], False

        if not result.get('success'):
            # The API's own way of saying "no match" — a real, successful check.
            return [], True

        out = []
        seen_names = set()
        for item in (result.get('result') or [])[:25]:
            sources = item.get('sources') or ['Unknown source']
            name = sources[0]
            if name in seen_names:
                continue
            seen_names.add(name)
            # NOTE: we deliberately do not read item.get('password') here.
            out.append({'source': name})
        return out, True
