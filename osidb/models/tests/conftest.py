import pytest

from osidb.models.flaw.cvss import FlawCVSS
from osidb.tests.factories import (
    FlawCVSSFactory,
    FlawFactory,
    PsModuleFactory,
    PsProductFactory,
    PsUpdateStreamFactory,
)


def _make_ps_hierarchy(business_unit="RHEL", moderate=False, default=False):
    """Create PsProduct → PsModule → PsUpdateStream and return the stream."""
    ps_product = PsProductFactory(business_unit=business_unit)
    ps_module = PsModuleFactory(ps_product=ps_product)
    return ps_module, PsUpdateStreamFactory(
        ps_module=ps_module,
        active_to_ps_module=ps_module,
        default_to_ps_module=ps_module if default else None,
        moderate_to_ps_module=ps_module if moderate else None,
        unacked_to_ps_module=None,
    )


@pytest.fixture
def ps_update_stream_no_module():
    return PsUpdateStreamFactory(ps_module=None)


@pytest.fixture
def ps_stream_not_moderate():
    """Non-community stream that is neither moderate nor default."""
    _, stream = _make_ps_hierarchy(moderate=False, default=False)
    return stream


@pytest.fixture
def ps_stream_with_default():
    """Non-community stream with default_to_ps_module set (IMPORTANT/CRITICAL tracker stream)."""
    _, stream = _make_ps_hierarchy(moderate=False, default=True)
    return stream


@pytest.fixture
def ps_stream_moderate_no_default():
    """Non-community stream that is moderate but has no default streams on the module."""
    _, stream = _make_ps_hierarchy(moderate=True, default=False)
    return stream


@pytest.fixture
def ps_stream_moderate_no_tracker_streams():
    """
    Non-community stream whose module has no moderate or unacked tracker streams.

    The stream's ps_module FK points to module_A (used for OOSS check via is_moderate),
    but moderate_to_ps_module points to module_B so that module_A.moderate_ps_update_streams
    is empty — triggering WONTFIX for LOW/MODERATE impacts.
    """
    ps_product = PsProductFactory(business_unit="RHEL")
    module_a = PsModuleFactory(ps_product=ps_product)
    module_b = PsModuleFactory(ps_product=ps_product)
    # Stream belongs to module_a, but its moderate link points to module_b
    stream = PsUpdateStreamFactory(
        ps_module=module_a,
        active_to_ps_module=module_a,
        moderate_to_ps_module=module_b,
        default_to_ps_module=None,
        unacked_to_ps_module=None,
    )
    return stream


@pytest.fixture
def ps_stream_with_moderate_tracker():
    """
    Non-community stream that is moderate and has a separate moderate tracker stream
    defined on the module, so it passes both OOSS and WONTFIX checks.
    """
    ps_product = PsProductFactory(business_unit="RHEL")
    ps_module = PsModuleFactory(ps_product=ps_product)
    return PsUpdateStreamFactory(
        ps_module=ps_module,
        active_to_ps_module=ps_module,
        moderate_to_ps_module=ps_module,
        unacked_to_ps_module=None,
    )


@pytest.fixture
def community_ps_stream_not_moderate():
    """Community stream that is neither default nor moderate."""
    _, stream = _make_ps_hierarchy(
        business_unit="Community", moderate=False, default=False
    )
    return stream


@pytest.fixture
def community_ps_stream_default_only():
    """Community stream that is default but not moderate (default counts as full support for community)."""
    _, stream = _make_ps_hierarchy(
        business_unit="Community", moderate=False, default=True
    )
    return stream


@pytest.fixture
def community_ps_stream_with_tracker():
    """
    Community stream that is both default and moderate, with a tracker stream defined,
    so it passes OOSS and WONTFIX checks and reaches the DELEGATED fallback.
    """
    ps_product = PsProductFactory(business_unit="Community")
    ps_module = PsModuleFactory(ps_product=ps_product)
    return PsUpdateStreamFactory(
        ps_module=ps_module,
        active_to_ps_module=ps_module,
        default_to_ps_module=ps_module,
        moderate_to_ps_module=ps_module,
        unacked_to_ps_module=None,
    )


@pytest.fixture
def flaw_with_cvss():
    """
    Factory fixture: call with (impact, cvss_vector) to get a saved Flaw with
    an RH CVSSv3 score. Pass cvss_vector=None to get a flaw with no CVSS scores.
    """

    def _make(impact, cvss_vector=None):
        flaw = FlawFactory(impact=impact)
        if cvss_vector is not None:
            FlawCVSSFactory(
                flaw=flaw,
                issuer=FlawCVSS.CVSSIssuer.REDHAT,
                version=FlawCVSS.CVSSVersion.VERSION3,
                vector=cvss_vector,
            )
        return flaw

    return _make
