from osidb.models import Flaw
from osidb.models.flaw import FlawSource

REDHAT_IDENTIFIED_SOURCES = {FlawSource.REDHAT}


def _is_public_feed_only(flaw: Flaw) -> bool:
    return bool(flaw.source and FlawSource(flaw.source).is_from_snippet)


def is_flaw_upstream_notifiable(flaw: Flaw) -> bool:
    if flaw.is_embargoed:
        return False

    source = FlawSource(flaw.source)
    if source in REDHAT_IDENTIFIED_SOURCES:
        return True
    if _is_public_feed_only(flaw):
        return False

    return False
