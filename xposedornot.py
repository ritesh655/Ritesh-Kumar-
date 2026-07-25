"""
XposedOrNot provider.

XposedOrNot offers a free check-email endpoint that doesn't require an
API key for basic lookups; api_key is accepted here for parity with the
other providers and for their paid tier, but is not required.

NOTE: verify the response shape against XposedOrNot's current API docs
(https://xposedornot.com/api_doc) before relying on this in production.
"""

import logging
import requests

from .base_provider import BaseProvider

logger = logging.getLogger(__name__)


class XposedOrNotProvider(BaseProvider):
    name = "XposedOrNot"

    def __init__(self, api_key=None):
        self.api_key = api_key

    def check_email(self, email):
        try:
            url = f"https://api.xposedornot.com/v1/check-email/{email}"
            headers = {"Authorization": f"Bearer {self.api_key}"} if self.api_key else {}
            response = requests.get(url, headers=headers, timeout=10)
            if response.status_code == 404:
                return [], True
            if response.status_code != 200:
                logger.warning(f"XposedOrNot provider returned HTTP {response.status_code}")
                return [], False
            result = response.json()
        except Exception as e:
            logger.warning(f"XposedOrNot provider call failed: {e}")
            return [], False

        breaches = result.get('breaches')
        if not breaches:
            return [], True

        out = []
        seen_names = set()
        # XposedOrNot nests breach names in sub-lists.
        flat = [name for group in breaches for name in (group if isinstance(group, list) else [group])]
        for name in flat:
            if not name or name in seen_names:
                continue
            seen_names.add(name)
            out.append({'source': name})
        return out, True
