from unittest.mock import mock_open, patch

import pytest
from django.utils.timezone import datetime, make_aware, timedelta

from apps.sla.framework import SLAContext, SLAFramework
from osidb.models import (
    Affect,
    CompliancePriority,
    Flaw,
    Impact,
    PsUpdateStream,
    Tracker,
)
from osidb.tests.factories import (
    AffectFactory,
    FlawFactory,
    PsModuleFactory,
    TrackerFactory,
)

pytestmark = pytest.mark.unit


class TestSLAFramework:
    """
    test SLAFramework functionality
    """

    class TestLoad:
        """
        test SLA policies loading
        """

        def test_single(self):
            """
            test that a policy definition is loaded properly
            """
            sla_file = """
# some comment
---
name: Low
description: SLA policy applied to low impact
conditions:
  affect:
    - aggregated impact is low
    - is not community
  flaw:
    - is not embargoed
    - state is not triage
sla:
  duration: 180
  start:
    latest:
      - reported date
      - unembargo date
  type: calendar days
"""

            with patch("builtins.open", mock_open(read_data=sla_file)):
                sla_framework = SLAFramework()

                assert sla_framework.policies
                assert len(sla_framework.policies) == 1
                policy = sla_framework.policies[0]
                assert policy.name == "Low"
                assert policy.description == "SLA policy applied to low impact"
                assert policy.conditions
                assert policy.sla
                # more details are tested as part of SLA model tests

        def test_multiple(self):
            """
            test that multiple policy definitions are loaded properly
            """
            sla_file = """
---
name: Moderate Compliance Priority
description: >
  SLA policy applied to moderate impact on
  compliance priority module and component
conditions:
  affect:
    - aggregated impact is moderate
    - is compliance priority
    - is not community
  flaw:
    - is not embargoed
    - state is not triage
sla:
  duration: 50
  start:
    latest:
      - reported date
      - unembargo date
  type: calendar days

---
name: Moderate
description: SLA policy applied to moderate impact
conditions:
  affect:
    - aggregated impact is moderate
    - is not community
  flaw:
    - is not embargoed
    - state is not triage
sla:
  duration: 90
  start:
    latest:
      - reported date
      - unembargo date
  type: calendar days

---
name: Low
description: SLA policy applied to low impact
conditions:
  affect:
    - aggregated impact is low
    - is not community
  flaw:
    - is not embargoed
    - state is not triage
sla:
  duration: 180
  start:
    latest:
      - reported date
      - unembargo date
  type: calendar days
"""

            with patch("builtins.open", mock_open(read_data=sla_file)):
                sla_framework = SLAFramework()

                assert sla_framework.policies
                assert len(sla_framework.policies) == 3
                # the order matters so check that it is preserved
                assert sla_framework.policies[0].name == "Moderate Compliance Priority"
                assert sla_framework.policies[1].name == "Moderate"
                assert sla_framework.policies[2].name == "Low"

    class TestClassify:
        """
        test that a model instance is properly
        classified to the correct SLA context
        """

        def test_single(self):
            """
            test that a policy classification works
            """
            flaw = FlawFactory(embargoed=False)
            ps_module = PsModuleFactory()
            affect = AffectFactory(
                flaw=flaw,
                affectedness=Affect.AffectAffectedness.AFFECTED,
                resolution=Affect.AffectResolution.DELEGATED,
                ps_module=ps_module.name,
            )
            tracker = TrackerFactory(
                affects=[affect],
                embargoed=flaw.embargoed,
                type=Tracker.BTS2TYPE[ps_module.bts_name],
            )

            sla_file = """
---
name: fantastic SLA policy
description: there is no better
conditions:
  flaw:
    - is not embargoed
sla:
  duration: 5
  start: created date
  type: calendar days
"""

            with patch("builtins.open", mock_open(read_data=sla_file)):
                sla_framework = SLAFramework()
                sla_context = sla_framework.classify(tracker)

                assert sla_context.sla
                assert sla_context.start == flaw.created_dt
                assert sla_context.end == flaw.created_dt + timedelta(days=5)

        @pytest.mark.parametrize(
            "reported_dt1,reported_dt2,mi_duration,ne_duration",
            [
                (
                    datetime(2000, 1, 1),
                    datetime(2000, 1, 1),
                    5,
                    10,
                ),
                (
                    datetime(2000, 1, 1),
                    datetime(2000, 1, 10),
                    5,
                    5,
                ),
                (
                    datetime(2000, 1, 10),
                    datetime(2000, 1, 1),
                    5,
                    20,
                ),
            ],
        )
        def test_multiple(self, reported_dt1, reported_dt2, mi_duration, ne_duration):
            """
            test that a policy classification works correctly when
            multiple policies and related affects/flaws are involved
            """
            flaw1 = FlawFactory(
                embargoed=False,
                major_incident_state=Flaw.FlawMajorIncident.APPROVED,
                reported_dt=make_aware(reported_dt1),
            )
            flaw2 = FlawFactory(
                embargoed=flaw1.embargoed,
                major_incident_state=Flaw.FlawMajorIncident.NOVALUE,
                reported_dt=make_aware(reported_dt2),
            )
            ps_module = PsModuleFactory()
            affect1 = AffectFactory(
                flaw=flaw1,
                affectedness=Affect.AffectAffectedness.AFFECTED,
                resolution=Affect.AffectResolution.DELEGATED,
                ps_module=ps_module.name,
            )
            affect2 = AffectFactory(
                flaw=flaw2,
                affectedness=Affect.AffectAffectedness.AFFECTED,
                resolution=Affect.AffectResolution.DELEGATED,
                ps_module=ps_module.name,
                ps_component=affect1.ps_component,
            )
            tracker = TrackerFactory(
                affects=[affect1, affect2],
                embargoed=flaw1.embargoed,
                type=Tracker.BTS2TYPE[ps_module.bts_name],
            )

            sla_file = f"""
---
name: Major Incident
description: only for very serious cases
conditions:
  flaw:
    - major incident state is approved
sla:
  duration: {mi_duration}
  start: reported date
  type: calendar days

---
name: Not Embargoed
description: suitable for whatever we find on the street
conditions:
  flaw:
    - is not embargoed
sla:
  duration: {ne_duration}
  start: reported date
  type: calendar days
"""

            with patch("builtins.open", mock_open(read_data=sla_file)):
                sla_framework = SLAFramework()

                # make sure that both contexts are accepted
                # each by a different plicy out of the two
                assert sla_framework.policies[0].accepts(
                    SLAContext(
                        affect=affect1,
                        flaw=flaw1,
                        tracker=tracker,
                    )
                )
                assert sla_framework.policies[1].accepts(
                    SLAContext(
                        affect=affect2,
                        flaw=flaw2,
                        tracker=tracker,
                    )
                )

                sla_context = sla_framework.classify(tracker)

                # the first context is the one resulting in the earlist SLA
                # end so it should be the outcome of the classification
                assert "flaw" in sla_context
                assert sla_context["flaw"] == flaw1
                assert "affect" in sla_context
                assert sla_context["affect"] == affect1
                assert "tracker" in sla_context
                assert sla_context["tracker"] == tracker
                assert sla_context.sla
                assert sla_context.start == flaw1.reported_dt
                assert sla_context.end == flaw1.reported_dt + timedelta(
                    days=mi_duration
                )

        @pytest.mark.parametrize(
            "is_compliance_priority",
            [
                (True),
                (False),
            ],
        )
        def test_tracker_sla(self, is_compliance_priority):
            """
            test that classification work also with an SLA property belonging to the tracker
            """
            flaw = FlawFactory(
                embargoed=False,
                impact=Impact.MODERATE,
                major_incident_state=Flaw.FlawMajorIncident.NOVALUE,
            )
            ps_module = PsModuleFactory(name="ps-module")
            affect = AffectFactory(
                flaw=flaw,
                impact=Impact.MODERATE,
                affectedness=Affect.AffectAffectedness.AFFECTED,
                resolution=Affect.AffectResolution.DELEGATED,
                ps_module=ps_module.name,
                ps_component="component-1",
            )
            PsUpdateStream(
                name="upd-stream-1",
                ps_module=ps_module,
                active_to_ps_module=ps_module,
                unacked_to_ps_module=ps_module,
            ).save()
            if is_compliance_priority:
                CompliancePriority(
                    ps_module=ps_module.name,
                    components=["component-0", "component-1", "component-2"],
                    streams=["upd-stream-1", "stream-1.3.z"],
                ).save()
            tracker = TrackerFactory(
                affects=[affect],
                embargoed=flaw.embargoed,
                type=Tracker.BTS2TYPE[ps_module.bts_name],
                ps_update_stream="upd-stream-1",
            )
            assert tracker.is_compliance_priority is is_compliance_priority

            sla_file = """
name: policy used for compliance-priority
description: >
  See real Compliance Priority policies in sla.yml.
  This test tests that the tracker's .is_compliance_priority
  is evaluated. It doesn't test the advance "sla:" options
  used in the real sla.yml file.
conditions:
  tracker:
    - is compliance priority
  affect:
    - aggregated impact is moderate
    - is not community
  flaw:
    - is not embargoed
sla:
  duration: 5
  start: created date
  type: calendar days
"""

            with patch("builtins.open", mock_open(read_data=sla_file)):
                sla_framework = SLAFramework()
                sla_context = sla_framework.classify(tracker)

                if is_compliance_priority:
                    assert sla_context.sla
                    assert sla_context.start == flaw.created_dt
                    assert sla_context.end == flaw.created_dt + timedelta(days=5)
                else:
                    assert not sla_context.sla
