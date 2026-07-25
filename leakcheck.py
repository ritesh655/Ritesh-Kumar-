"""
LeakCheck provider.

NOTE: verify the response shape against LeakCheck's current API docs
(https://leakcheck.io/api) before relying on this in production —
field names below reflect their documented v2 query endpoint at the
time this was written, but third-party API contracts can change.
"""

import logging
import requests

from .base_provider import BaseProvider

logger = logging.getLogger(__name__)


class LeakCheckProvider(BaseProvider):
    name = "LeakCheck"

    def __init__(self, api_key):
        self.api_key = api_key

    def check_email(self, email):
        if not self.api_key:
            return [], False
        try:
            url = f"https://leakcheck.io/api/v2/query/{email}"
            headers = {"X-API-Key": self.api_key}
            response = requests.get(url, headers=headers, timeout=10)
            if response.status_code != 200:
                logger.warning(f"LeakCheck provider returned HTTP {response.status_code}")
                return [], False
            result = response.json()
        except Exception as e:
            logger.warning(f"LeakCheck provider call failed: {e}")
            return [], False

        if not result.get('success'):
            return [], False

        if not result.get('found'):
            return [], True

        out = []
        seen_names = set()
        for item in (result.get('result') or []):
            name = item.get('source', {}).get('name') if isinstance(item.get('source'), dict) else item.get('source')
            name = name or 'Unknown source'
            if name in seen_names:
                continue
            seen_names.add(name)
            out.append({'source': name})
        return out, True
