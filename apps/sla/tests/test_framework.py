import pytest
import yaml
from django.utils.timezone import datetime, make_aware, timedelta

from apps.sla.framework import SLAContext, SLAPolicy, sla_classify
from osidb.models import Affect, Flaw, Impact, PsUpdateStream, Tracker
from osidb.tests.factories import (
    AffectFactory,
    FlawFactory,
    PsModuleFactory,
    PsUpdateStreamFactory,
    TrackerFactory,
)

pytestmark = pytest.mark.unit


def load_sla_policies(sla_file):
    """
    Helper function to load SLA policies into the database using a
    string representing the contents of an SLA file.
    """
    for order, policy_desc in enumerate(yaml.safe_load_all(sla_file)):
        policy = SLAPolicy.create_from_description(policy_desc, order)
        policy.save()


class TestSLAFramework:
    """
    test SLA framework functionality
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

            load_sla_policies(sla_file)

            assert SLAPolicy.objects.count() == 1
            policy = SLAPolicy.objects.first()
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
name: Critical
description: >
  SLA policy applied to critical impact
conditions:
  affect:
    - aggregated impact is critical
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

            load_sla_policies(sla_file)
            assert SLAPolicy.objects.count() == 3
            sla_policies = SLAPolicy.objects.all()
            # the order matters so check that it is preserved
            assert sla_policies[0].name == "Critical"
            assert sla_policies[1].name == "Moderate"
            assert sla_policies[2].name == "Low"

        def test_date_sources(self):
            """
            test that a policy definition with multiple date sources is loaded correctly
            """
            sla_file = """
# some comment
---
name: Low
description: SLA policy applied to low impact
conditions:
  affect:
    - aggregated impact is low
  flaw:
    - is not embargoed
sla:
  duration: 180
  start:
    latest:
      flaw:
        - reported date
        - unembargo date
      tracker:
        - created date
  type: calendar days
"""

            load_sla_policies(sla_file)

            assert SLAPolicy.objects.count() == 1
            policy = SLAPolicy.objects.first()
            assert policy.name == "Low"
            assert policy.description == "SLA policy applied to low impact"
            assert policy.conditions
            assert policy.sla

        @pytest.mark.parametrize(
            "type_desc,expected_ending,expected_type",
            [
                (
                    "calendar days",
                    "any day",
                    "calendar days",
                ),
                (
                    "business days any day",
                    "any day",
                    "business days",
                ),
                (
                    "no week ending calendar days",
                    "no week ending",
                    "calendar days",
                ),
            ],
        )
        def test_ending(self, type_desc, expected_ending, expected_type):
            """
            test that a policy ending is correctly loaded from the definition
            """
            sla_file = f"""
# some comment
---
name: Low
description: SLA policy applied to low impact
conditions:
  affect:
    - aggregated impact is low
  flaw:
    - is not embargoed
sla:
  duration: 180
  start:
    latest:
      flaw:
        - reported date
        - unembargo date
      tracker:
        - created date
  type: {type_desc}
"""

            load_sla_policies(sla_file)

            assert SLAPolicy.objects.count() == 1
            policy = SLAPolicy.objects.first()
            assert policy.sla
            assert policy.sla.duration_type == expected_type
            assert policy.sla.ending == expected_ending

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
            ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)
            tracker = TrackerFactory(
                affects=[affect],
                embargoed=flaw.embargoed,
                ps_update_stream=ps_update_stream.name,
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

            load_sla_policies(sla_file)
            sla_context = sla_classify(tracker)

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
            ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)
            tracker = TrackerFactory(
                affects=[affect1, affect2],
                embargoed=flaw1.embargoed,
                ps_update_stream=ps_update_stream.name,
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

            load_sla_policies(sla_file)

            policies = SLAPolicy.objects.all()
            assert policies[0].accepts(
                SLAContext(
                    affect=affect1,
                    flaw=flaw1,
                    tracker=tracker,
                )
            )
            assert policies[1].accepts(
                SLAContext(
                    affect=affect2,
                    flaw=flaw2,
                    tracker=tracker,
                )
            )

            sla_context = sla_classify(tracker)

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
            assert sla_context.end == flaw1.reported_dt + timedelta(days=mi_duration)

        @pytest.mark.parametrize(
            "is_closed",
            [
                (True),
                (False),
            ],
        )
        def test_tracker_sla(self, is_closed):
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
            status = "CLOSED" if is_closed else "NEW"
            tracker = TrackerFactory(
                affects=[affect],
                embargoed=flaw.embargoed,
                type=Tracker.BTS2TYPE[ps_module.bts_name],
                ps_update_stream="upd-stream-1",
                status=status,
            )
            assert tracker.is_closed is is_closed

            sla_file = """
name: policy used for closed trackers
description: >
  this is actually an unrealistic scenario
conditions:
  tracker:
    - is closed
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

            load_sla_policies(sla_file)
            sla_context = sla_classify(tracker)

            if is_closed:
                assert sla_context.sla
                assert sla_context.start == flaw.created_dt
                assert sla_context.end == flaw.created_dt + timedelta(days=5)
            else:
                assert not sla_context.sla
