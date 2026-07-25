"""
Base interface for breach-data providers.

Every provider (BreachDirectory, HIBP, LeakCheck, XposedOrNot, or a future
one) must subclass BaseProvider and implement check_email(). This is the
ONLY thing app.py's aggregate_breach_sources() relies on — so a new
provider can be added by dropping in one new module here, without
touching app.py, routes, templates, or any other application code.

Contract (unchanged from the original inline implementation, so existing
callers in app.py keep working exactly as before):

    check_email(email) -> (matches, ok)

    matches: list of dicts, each shaped like {'source': <breach name>}.
             This deliberately never includes a password/credential value —
             providers must only surface the FACT of exposure, never the
             secret itself (see app.py's SECURITY FIX 2026-07-22 note).
    ok:      True  -> the provider call completed (even if it found
                       nothing — an empty list + ok=True is a real
                       "not found" result).
             False -> the provider call itself failed (timeout, network
                       error, bad response, missing API key). Callers
                       must NOT treat this as a clean/safe result.

check_username(), check_password(), and check_phone() are defined here as
optional extension points for providers that support them. None of the
providers wired up today implement them, and app.py does not call them —
they exist so a future provider module can add that capability without
requiring an interface change.
"""

from abc import ABC, abstractmethod


class BaseProvider(ABC):
    """Every concrete provider must implement check_email(). The other
    methods are optional — default implementations report 'unsupported'
    rather than raising, so a provider that only supports email lookups
    (which is all any provider here supports today) doesn't need to
    override anything else."""

    name = "base"

    @abstractmethod
    def check_email(self, email):
        """Returns (matches, ok) — see contract above."""
        raise NotImplementedError

    def check_username(self, username):
        return [], False

    def check_password(self, password):
        return [], False

    def check_phone(self, phone):
        return [], False
