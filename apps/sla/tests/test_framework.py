import pytest
import yaml
from django.utils.timezone import datetime, make_aware, timedelta

from apps.sla.models import SLOPolicy, TemporalContext
from osidb.models import Affect, Flaw, Impact, PsUpdateStream, Tracker
from osidb.tests.factories import (
    AffectFactory,
    FlawFactory,
    PsModuleFactory,
    PsUpdateStreamFactory,
    TrackerFactory,
)

pytestmark = pytest.mark.unit


def load_policies(policy_cls, slo_file):
    """
    Helper function to load policies into the database using a
    string representing the contents of a policy file.
    """
    for order, policy_desc in enumerate(yaml.safe_load_all(slo_file)):
        policy = policy_cls.create_from_description(policy_desc, order)
        policy.save()


class TestSLAFramework:
    """
    test SLA/SLO framework functionality
    """

    class TestLoad:
        """
        test SLO policies loading
        """

        def test_single(self):
            """
            test that a policy definition is loaded properly
            """
            slo_file = """
# some comment
---
name: Low
description: SLO policy applied to low impact
conditions:
  affect:
    - aggregated impact is low
    - is not community
  flaw:
    - is not embargoed
    - state is not triage
slo:
  duration: 180
  start:
    latest:
      - reported date
      - unembargo date
  type: calendar days
"""

            load_policies(SLOPolicy, slo_file)

            assert SLOPolicy.objects.count() == 1
            policy = SLOPolicy.objects.first()
            assert policy.name == "Low"
            assert policy.description == "SLO policy applied to low impact"
            assert policy.conditions
            assert policy.slo
            # more details are tested as part of SLO model tests

        def test_multiple(self):
            """
            test that multiple policy definitions are loaded properly
            """
            slo_file = """
---
name: Critical
description: >
  SLO policy applied to critical impact
conditions:
  affect:
    - aggregated impact is critical
    - is not community
  flaw:
    - is not embargoed
    - state is not triage
slo:
  duration: 50
  start:
    latest:
      - reported date
      - unembargo date
  type: calendar days

---
name: Moderate
description: SLO policy applied to moderate impact
conditions:
  affect:
    - aggregated impact is moderate
    - is not community
  flaw:
    - is not embargoed
    - state is not triage
slo:
  duration: 90
  start:
    latest:
      - reported date
      - unembargo date
  type: calendar days

---
name: Low
description: SLO policy applied to low impact
conditions:
  affect:
    - aggregated impact is low
    - is not community
  flaw:
    - is not embargoed
    - state is not triage
slo:
  duration: 180
  start:
    latest:
      - reported date
      - unembargo date
  type: calendar days
"""

            load_policies(SLOPolicy, slo_file)
            assert SLOPolicy.objects.count() == 3
            slo_policies = SLOPolicy.objects.all()
            # the order matters so check that it is preserved
            assert slo_policies[0].name == "Critical"
            assert slo_policies[1].name == "Moderate"
            assert slo_policies[2].name == "Low"

        def test_date_sources(self):
            """
            test that a policy definition with multiple date sources is loaded correctly
            """
            slo_file = """
# some comment
---
name: Low
description: SLO policy applied to low impact
conditions:
  affect:
    - aggregated impact is low
  flaw:
    - is not embargoed
slo:
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

            load_policies(SLOPolicy, slo_file)

            assert SLOPolicy.objects.count() == 1
            policy = SLOPolicy.objects.first()
            assert policy.name == "Low"
            assert policy.description == "SLO policy applied to low impact"
            assert policy.conditions
            assert policy.slo

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
            slo_file = f"""
# some comment
---
name: Low
description: SLO policy applied to low impact
conditions:
  affect:
    - aggregated impact is low
  flaw:
    - is not embargoed
slo:
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

            load_policies(SLOPolicy, slo_file)

            assert SLOPolicy.objects.count() == 1
            policy = SLOPolicy.objects.first()
            assert policy.slo
            assert policy.slo.duration_type == expected_type
            assert policy.slo.ending_types == [expected_ending]

        @pytest.mark.parametrize(
            "type_desc,ending,expected_ending,expected_type",
            [
                (
                    "calendar days",
                    "any day",
                    "any day",
                    "calendar days",
                ),
                (
                    "business days",
                    "any day",
                    "any day",
                    "business days",
                ),
                (
                    "business days",
                    "no week ending",
                    "no week ending",
                    "business days",
                ),
            ],
        )
        def test_ending_dict(self, type_desc, ending, expected_ending, expected_type):
            """
            test that a policy ending is correctly loaded from the definition as a dictionary
            """
            slo_file = f"""
# some comment
---
name: Low
description: SLO policy applied to low impact
conditions:
  affect:
    - aggregated impact is low
  flaw:
    - is not embargoed
slo:
  duration: 180
  start:
    latest:
      flaw:
        - reported date
        - unembargo date
      tracker:
        - created date
  type:
    days: {type_desc}
    ending:
      - {ending}
"""

            load_policies(SLOPolicy, slo_file)

            assert SLOPolicy.objects.count() == 1
            policy = SLOPolicy.objects.first()
            assert policy.slo
            assert policy.slo.duration_type == expected_type
            assert policy.slo.ending_types == [expected_ending]

        @pytest.mark.parametrize(
            "type_desc,ending1,ending2,expected_ending,expected_type",
            [
                (
                    "calendar days",
                    "any day",
                    "no shutdown",
                    "any day",
                    "calendar days",
                ),
                (
                    "business days",
                    "any day",
                    "no shutdown",
                    "any day",
                    "business days",
                ),
                (
                    "business days",
                    "no week ending",
                    "no shutdown",
                    "no week ending",
                    "business days",
                ),
            ],
        )
        def test_multiple_endings_dict(
            self, type_desc, ending1, ending2, expected_ending, expected_type
        ):
            """
            test that a policy ending is correctly loaded from the definition as a dictionary
            """
            slo_file = f"""
# some comment
---
name: Low
description: SLO policy applied to low impact
conditions:
  affect:
    - aggregated impact is low
  flaw:
    - is not embargoed
slo:
  duration: 180
  start:
    latest:
      flaw:
        - reported date
        - unembargo date
      tracker:
        - created date
  type:
    days: {type_desc}
    ending:
      - {ending1}
      - {ending2}
"""

            load_policies(SLOPolicy, slo_file)

            assert SLOPolicy.objects.count() == 1
            policy = SLOPolicy.objects.first()
            assert policy.slo
            assert policy.slo.duration_type == expected_type
            assert policy.slo.ending_types == [ending1, ending2]

        @pytest.mark.parametrize(
            "type_desc,expected_ending,expected_type",
            [
                (
                    "calendar days",
                    "any day",
                    "calendar days",
                ),
                (
                    "business days",
                    "any day",
                    "business days",
                ),
            ],
        )
        def test_no_endings_dict(self, type_desc, expected_ending, expected_type):
            """
            test that a policy ending is correctly loaded from the definition as a dictionary
            """
            slo_file = f"""
# some comment
---
name: Low
description: SLO policy applied to low impact
conditions:
  affect:
    - aggregated impact is low
  flaw:
    - is not embargoed
slo:
  duration: 180
  start:
    latest:
      flaw:
        - reported date
        - unembargo date
      tracker:
        - created date
  type:
    days: {type_desc}
"""

            load_policies(SLOPolicy, slo_file)

            assert SLOPolicy.objects.count() == 1
            policy = SLOPolicy.objects.first()
            assert policy.slo
            assert policy.slo.duration_type == expected_type
            assert policy.slo.ending_types == ["any day"]

        def test_null_slo(self):
            """
            Test that a policy with a null SLO is correctly loaded from the definition
            """
            slo_file = """
---
name: Null SLO
description: Null SLO
conditions:
  affect:
    - aggregated impact is low
slo: null
"""
            load_policies(SLOPolicy, slo_file)

            assert SLOPolicy.objects.count() == 1
            policy = SLOPolicy.objects.first()
            assert policy.slo is None

    class TestClassify:
        """
        test that a model instance is properly
        classified to the correct SLO context
        """

        def test_single(self):
            """
            test that a policy classification works
            """
            flaw = FlawFactory(embargoed=False)
            ps_module = PsModuleFactory()
            ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)
            affect = AffectFactory(
                flaw=flaw,
                affectedness=Affect.AffectAffectedness.AFFECTED,
                resolution=Affect.AffectResolution.DELEGATED,
                ps_update_stream=ps_update_stream.name,
            )
            tracker = TrackerFactory(
                affects=[affect],
                embargoed=flaw.embargoed,
                ps_update_stream=ps_update_stream.name,
                type=Tracker.BTS2TYPE[ps_module.bts_name],
            )

            slo_file = """
---
name: fantastic SLO policy
description: there is no better
conditions:
  flaw:
    - is not embargoed
slo:
  duration: 5
  start: created date
  type: calendar days
"""

            load_policies(SLOPolicy, slo_file)
            slo_context = SLOPolicy.classify(tracker)

            assert slo_context.policy
            assert slo_context.start == flaw.created_dt
            assert slo_context.end == flaw.created_dt + timedelta(days=5)

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
                major_incident_state=Flaw.FlawMajorIncident.MAJOR_INCIDENT_APPROVED,
                reported_dt=make_aware(reported_dt1),
            )
            flaw2 = FlawFactory(
                embargoed=flaw1.embargoed,
                major_incident_state=Flaw.FlawMajorIncident.NOVALUE,
                reported_dt=make_aware(reported_dt2),
            )
            ps_module = PsModuleFactory()
            ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)
            affect1 = AffectFactory(
                flaw=flaw1,
                affectedness=Affect.AffectAffectedness.AFFECTED,
                resolution=Affect.AffectResolution.DELEGATED,
                ps_update_stream=ps_update_stream.name,
            )
            affect2 = AffectFactory(
                flaw=flaw2,
                affectedness=Affect.AffectAffectedness.AFFECTED,
                resolution=Affect.AffectResolution.DELEGATED,
                ps_update_stream=ps_update_stream.name,
                ps_component=affect1.ps_component,
            )
            tracker = TrackerFactory(
                affects=[affect1, affect2],
                embargoed=flaw1.embargoed,
                ps_update_stream=ps_update_stream.name,
                type=Tracker.BTS2TYPE[ps_module.bts_name],
            )

            slo_file = f"""
---
name: Major Incident
description: only for very serious cases
conditions:
  flaw:
    - major incident state is major incident approved
slo:
  duration: {mi_duration}
  start: reported date
  type: calendar days

---
name: Not Embargoed
description: suitable for whatever we find on the street
conditions:
  flaw:
    - is not embargoed
slo:
  duration: {ne_duration}
  start: reported date
  type: calendar days
"""

            load_policies(SLOPolicy, slo_file)

            policies = SLOPolicy.objects.all()
            assert policies[0].accepts(
                TemporalContext(
                    affect=affect1,
                    flaw=flaw1,
                    tracker=tracker,
                )
            )
            assert policies[1].accepts(
                TemporalContext(
                    affect=affect2,
                    flaw=flaw2,
                    tracker=tracker,
                )
            )

            slo_context = SLOPolicy.classify(tracker)

            # the first context is the one resulting in the earlist SLO
            # end so it should be the outcome of the classification
            assert "flaw" in slo_context
            assert slo_context["flaw"] == flaw1
            assert "affect" in slo_context
            assert slo_context["affect"] == affect1
            assert "tracker" in slo_context
            assert slo_context["tracker"] == tracker
            assert slo_context.policy
            assert slo_context.start == flaw1.reported_dt
            assert slo_context.end == flaw1.reported_dt + timedelta(days=mi_duration)

        @pytest.mark.parametrize(
            "is_closed",
            [
                (True),
                (False),
            ],
        )
        def test_tracker_slo(self, is_closed):
            """
            test that classification work also with an SLO property belonging to the tracker
            """
            flaw = FlawFactory(
                embargoed=False,
                impact=Impact.MODERATE,
                major_incident_state=Flaw.FlawMajorIncident.NOVALUE,
            )
            ps_module = PsModuleFactory(name="ps-module")
            PsUpdateStream(
                name="upd-stream-1",
                ps_module=ps_module,
                active_to_ps_module=ps_module,
                unacked_to_ps_module=ps_module,
            ).save()
            affect = AffectFactory(
                flaw=flaw,
                impact=Impact.MODERATE,
                affectedness=Affect.AffectAffectedness.AFFECTED,
                resolution=Affect.AffectResolution.DELEGATED,
                ps_update_stream="upd-stream-1",
                ps_component="component-1",
            )
            status = "CLOSED" if is_closed else "NEW"
            tracker = TrackerFactory(
                affects=[affect],
                embargoed=flaw.embargoed,
                type=Tracker.BTS2TYPE[ps_module.bts_name],
                ps_update_stream="upd-stream-1",
                status=status,
            )
            assert tracker.is_closed is is_closed

            slo_file = """
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
slo:
  duration: 5
  start: created date
  type: calendar days
"""

            load_policies(SLOPolicy, slo_file)
            slo_context = SLOPolicy.classify(tracker)

            if is_closed:
                assert slo_context.policy
                assert slo_context.start == flaw.created_dt
                assert slo_context.end == flaw.created_dt + timedelta(days=5)
            else:
                assert not slo_context.policy

        @pytest.mark.parametrize(
            "component,excluded",
            [
                ("kpatch", True),
                ("glibc", False),
            ],
        )
        def test_exclusion(self, component, excluded):
            """
            Test that an exclusion policy placed as the first one using the 'in' condition
            works for not applying SLO when these conditions are met
            """
            slo_file = """
---
name: Excluded components
description: Components which do not need SLO
conditions:
  affect:
    - PS component in:
      - kpatch
      - kudos
      - kratos
slo: null
---
name: Low
description: SLO policy applied to low impact
conditions:
  affect:
    - aggregated impact is low
slo:
  duration: 5
  start: reported date
  type: calendar days
---
name: Major Incident
description: only for very serious cases
conditions:
  flaw:
    - major incident state is major incident approved
slo:
  duration: 2
  start: reported date
  type: calendar days
"""
            flaw = FlawFactory(
                embargoed=False,
                impact=Impact.LOW,
                major_incident_state=Flaw.FlawMajorIncident.NOVALUE,
            )
            ps_module = PsModuleFactory(name="rhel-8")
            ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)
            affect = AffectFactory(
                flaw=flaw,
                affectedness=Affect.AffectAffectedness.AFFECTED,
                resolution=Affect.AffectResolution.DELEGATED,
                ps_update_stream=ps_update_stream.name,
                ps_component=component,
                impact=Impact.LOW,
            )
            tracker = TrackerFactory(
                affects=[affect],
                embargoed=flaw.embargoed,
                ps_update_stream=ps_update_stream.name,
                type=Tracker.BTS2TYPE[ps_module.bts_name],
            )

            load_policies(SLOPolicy, slo_file)
            slo_context = SLOPolicy.classify(tracker)
            if excluded:
                assert not slo_context.policy
            else:
                assert slo_context.policy
                assert slo_context.start == flaw.reported_dt
                assert slo_context.end == flaw.created_dt + timedelta(days=5)
