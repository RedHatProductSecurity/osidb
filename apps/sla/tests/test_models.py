import pytest
from django.utils.timezone import datetime, make_aware, timedelta

from apps.sla.models import SLA, SLAContext, SLAPolicy
from apps.sla.time import add_business_days, add_days
from osidb.dmodels import Impact
from osidb.dmodels.affect import Affect
from osidb.dmodels.flaw.flaw import Flaw
from osidb.dmodels.tracker import Tracker
from osidb.tests.factories import (
    AffectFactory,
    FlawFactory,
    PsModuleFactory,
    PsProductFactory,
    PsUpdateStreamFactory,
    TrackerFactory,
)

pytestmark = pytest.mark.unit


class TestSLA:
    """
    test SLA parsing and computation
    """

    class TestParsing:
        """
        test SLA definition parsing
        """

        @pytest.mark.parametrize(
            "definition,expected",
            [(5, 5), ("50", 50), ("   5 ", 5)],
        )
        def test_duration(self, definition, expected):
            """
            test parsing of SLA duration
            """
            sla_desc = {
                "duration": definition,
                "start": "unembargo date",
                "type": "business days",
            }
            sla = SLA.create_from_description(sla_desc)

            assert sla.duration == expected

        @pytest.mark.parametrize(
            "definition,expected_func,expected_dates",
            [
                ("reported date", max, ["reported_dt"]),
                ("unembargo date", max, ["unembargo_dt"]),
                ({"latest": ["created date"]}, max, ["created_dt"]),
                ({"earliest": ["created date"]}, min, ["created_dt"]),
                (
                    {"earliest": ["created date", "updated date"]},
                    min,
                    ["created_dt", "updated_dt"],
                ),
                (
                    {
                        "latest": [
                            "major incident start date",
                            "reported date",
                            "unembargo date",
                        ]
                    },
                    max,
                    ["major_incident_start_dt", "reported_dt", "unembargo_dt"],
                ),
            ],
        )
        def test_start(self, definition, expected_func, expected_dates):
            """
            test parsing of SLA start
            """
            sla_desc = {
                "duration": 5,
                "start": definition,
                "type": "business days",
            }
            sla = SLA.create_from_description(sla_desc)

            assert sla.get_start == expected_func
            # No source is specified so by default it's flaw
            assert sla.start_dates["flaw"] == expected_dates

        @pytest.mark.parametrize(
            "definition,expected",
            [("business days", add_business_days), ("calendar days", add_days)],
        )
        def test_type(self, definition, expected):
            """
            test parsing of SLA type
            """
            sla_desc = {
                "duration": 5,
                "start": "unembargo date",
                "type": definition,
            }
            sla = SLA.create_from_description(sla_desc)

            assert sla.add_days == expected

    class TestStart:
        """
        test SLA start determination
        """

        @pytest.mark.parametrize(
            "definition,attribute,value",
            [
                ("created date", "created_dt", datetime(2022, 12, 20)),
                ("reported date", "reported_dt", datetime(2022, 12, 20)),
                (
                    "unembargo date",
                    "unembargo_dt",
                    datetime(2022, 12, 20, 13, 13, 13),
                ),
                ("updated date", "updated_dt", datetime(2022, 12, 20)),
            ],
        )
        def test_start_simple(self, definition, attribute, value):
            """
            test determination of SLA start defined by short definition
            """
            sla_desc = {
                "duration": 5,
                "start": definition,
                "type": "business days",
            }
            sla = SLA.create_from_description(sla_desc)

            flaw = FlawFactory()
            setattr(flaw, attribute, value)

            sla_context = SLAContext(flaw=flaw)
            assert sla.start(sla_context) == value

        @pytest.mark.parametrize(
            "definition,context,expected",
            [
                (
                    [
                        "created date",
                    ],
                    [
                        ("created_dt", datetime(2022, 12, 20)),
                    ],
                    datetime(2022, 12, 20),
                ),
                (
                    [
                        "created date",
                        "updated date",
                    ],
                    [
                        ("created_dt", datetime(2022, 12, 20)),
                        ("updated_dt", datetime(2022, 12, 22)),
                    ],
                    datetime(2022, 12, 20),
                ),
                (
                    [
                        "created date",
                        "updated date",
                    ],
                    [
                        ("created_dt", datetime(2022, 12, 22)),
                        ("updated_dt", datetime(2022, 12, 20)),
                    ],
                    datetime(2022, 12, 20),
                ),
                (
                    [
                        "created date",
                        "reported date",
                        "unembargo_dt",
                        "updated date",
                    ],
                    [
                        ("created_dt", datetime(2023, 12, 20)),
                        ("reported_dt", datetime(2022, 12, 21)),
                        ("unembargo_dt", datetime(2022, 11, 21)),
                        ("updated_dt", datetime(2022, 12, 22)),
                    ],
                    datetime(2022, 11, 21),
                ),
            ],
        )
        def test_start_earliest(self, definition, context, expected):
            """
            test determination of SLA start defined by earliest definition
            """
            sla_desc = {
                "duration": 5,
                "start": {
                    "earliest": definition,
                },
                "type": "business days",
            }
            sla = SLA.create_from_description(sla_desc)

            flaw = FlawFactory()
            for attribute, value in context:
                setattr(flaw, attribute, make_aware(value))
            sla_context = SLAContext(flaw=flaw)

            assert sla.start(sla_context) == make_aware(expected)

        @pytest.mark.parametrize(
            "definition,context,expected",
            [
                (
                    [
                        "created date",
                    ],
                    [
                        ("created_dt", datetime(2022, 12, 20)),
                    ],
                    datetime(2022, 12, 20),
                ),
                (
                    [
                        "created date",
                        "updated date",
                    ],
                    [
                        ("created_dt", datetime(2022, 12, 20)),
                        ("updated_dt", datetime(2022, 12, 22)),
                    ],
                    datetime(2022, 12, 22),
                ),
                (
                    [
                        "created date",
                        "updated date",
                    ],
                    [
                        ("created_dt", datetime(2022, 12, 22)),
                        ("updated_dt", datetime(2022, 12, 20)),
                    ],
                    datetime(2022, 12, 22),
                ),
                (
                    [
                        "created date",
                        "reported date",
                        "unembargo_dt",
                        "updated date",
                    ],
                    [
                        ("created_dt", datetime(2023, 12, 20)),
                        ("reported_dt", datetime(2022, 12, 21)),
                        ("unembargo_dt", datetime(2022, 11, 21)),
                        ("updated_dt", datetime(2022, 12, 22)),
                    ],
                    datetime(2023, 12, 20),
                ),
            ],
        )
        def test_start_latest(self, definition, context, expected):
            """
            test determination of SLA start defined by latest definition
            """
            sla_desc = {
                "duration": 5,
                "start": {
                    "latest": definition,
                },
                "type": "business days",
            }
            sla = SLA.create_from_description(sla_desc)

            flaw = FlawFactory()
            for attribute, value in context:
                setattr(flaw, attribute, make_aware(value))
            sla_context = SLAContext(flaw=flaw)

            assert sla.start(sla_context) == make_aware(expected)

        @pytest.mark.parametrize(
            "definition,context,expected",
            [
                (
                    {"flaw": ["unembargo date"], "tracker": ["created date"]},
                    {
                        "flaw": [
                            ("unembargo_dt", datetime(2022, 11, 21)),
                        ],
                        "tracker": [("created_dt", datetime(2023, 12, 20))],
                    },
                    datetime(2023, 12, 20),
                ),
                (
                    {"flaw": ["unembargo date"], "tracker": ["created date"]},
                    {
                        "flaw": [
                            ("unembargo_dt", datetime(2024, 11, 21)),
                        ],
                        "tracker": [("created_dt", datetime(2023, 12, 20))],
                    },
                    datetime(2024, 11, 21),
                ),
                (
                    {"tracker": ["created date"]},
                    {"tracker": [("created_dt", datetime(2023, 12, 20))]},
                    datetime(2023, 12, 20),
                ),
            ],
        )
        def test_date_source(self, definition, context, expected):
            sla_desc = {
                "duration": 5,
                "start": {
                    "latest": definition,
                },
                "type": "calendar days",
            }
            sla = SLA.create_from_description(sla_desc)

            flaw = FlawFactory()
            for attribute, value in context.get("flaw", {}):
                setattr(flaw, attribute, make_aware(value))
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
            for attribute, value in context.get("tracker", {}):
                setattr(tracker, attribute, make_aware(value))

            sla_context = SLAContext(flaw=flaw, affect=affect, tracker=tracker)

            assert sla.start(sla_context) == make_aware(expected)

    class TestEnd:
        """
        test SLA end computation
        """

        @pytest.mark.parametrize(
            "definition,expected",
            [
                # we consider US business days
                # so we have to add the time shift
                # plus round to the start of the day
                # which is then UTC 00:00 + 5 hours
                (1, datetime(2023, 11, 14, 5)),
                (5, datetime(2023, 11, 20, 5)),
                (30, datetime(2024, 1, 2, 5)),
                (50, datetime(2024, 1, 30, 5)),
            ],
        )
        def test_end_business(self, definition, expected):
            """
            test computation of SLA end in business days
            """
            sla_desc = {
                "duration": definition,
                "start": "reported date",
                "type": "business days",
            }
            sla = SLA.create_from_description(sla_desc)
            flaw = FlawFactory(reported_dt=make_aware(datetime(2023, 11, 13, 1, 1, 1)))
            sla_context = SLAContext(flaw=flaw)

            assert sla.end(sla_context) == make_aware(expected)

        @pytest.mark.parametrize(
            "definition,expected",
            [
                (1, datetime(2023, 11, 14, 5, 5, 5)),
                (5, datetime(2023, 11, 18, 5, 5, 5)),
                (30, datetime(2023, 12, 13, 5, 5, 5)),
                (50, datetime(2024, 1, 2, 5, 5, 5)),
            ],
        )
        def test_end_calendar(self, definition, expected):
            """
            test computation of SLA end in calendar days
            """
            sla_desc = {
                "duration": definition,
                "start": "reported date",
                "type": "calendar days",
            }
            sla = SLA.create_from_description(sla_desc)
            flaw = FlawFactory(reported_dt=make_aware(datetime(2023, 11, 13, 5, 5, 5)))
            sla_context = SLAContext(flaw=flaw)

            assert sla.end(sla_context) == make_aware(expected)


class TestSLAContext:
    """
    test SLAContext functionality
    """

    class TestMin:
        """
        test minimal SLAContext determination
        """

        @pytest.mark.parametrize(
            "definition1,attribute1,value1,definition2,attribute2,value2",
            [
                (
                    {
                        "duration": 5,
                        "start": "reported date",
                        "type": "calendar days",
                    },
                    "reported_dt",
                    datetime(2000, 1, 1),
                    {
                        "duration": 5,
                        "start": "reported date",
                        "type": "calendar days",
                    },
                    "reported_dt",
                    datetime(2000, 1, 3),
                ),
                (
                    {
                        "duration": 5,
                        "start": "reported date",
                        "type": "calendar days",
                    },
                    "reported_dt",
                    datetime(2000, 1, 1),
                    {
                        "duration": 5,
                        "start": "reported date",
                        "type": "business days",
                    },
                    "reported_dt",
                    datetime(2000, 1, 1),
                ),
                (
                    {
                        "duration": 5,
                        "start": "reported date",
                        "type": "business days",
                    },
                    "reported_dt",
                    datetime(2000, 1, 1),
                    {
                        "duration": 7,
                        "start": "reported date",
                        "type": "business days",
                    },
                    "reported_dt",
                    datetime(2000, 1, 1),
                ),
                (
                    {
                        "duration": 5,
                        "start": "unembargo date",
                        "type": "business days",
                    },
                    "unembargo_dt",
                    datetime(2000, 1, 1),
                    {
                        "duration": 7,
                        "start": "reported date",
                        "type": "business days",
                    },
                    "reported_dt",
                    datetime(2000, 1, 1),
                ),
            ],
        )
        def test_min(
            self, definition1, attribute1, value1, definition2, attribute2, value2
        ):
            """
            test that the minimal context which is the one
            resulting in earlies SLA end is correctly determined
            """
            policy_desc1 = {
                "name": "fantastic SLA policy",
                "description": "there is no better",
                "conditions": {},  # this is not valid but OK for this test case
                "sla": definition1,
            }
            policy1 = SLAPolicy.create_from_description(policy_desc1)
            flaw1 = FlawFactory()
            setattr(flaw1, attribute1, value1)
            sla_context1 = SLAContext(flaw=flaw1)
            sla_context1.sla = policy1.sla

            policy_desc2 = {
                "name": "fantastic SLA policy",
                "description": "there is no better",
                "conditions": {},  # this is not valid but OK for this test case
                "sla": definition2,
            }
            policy2 = SLAPolicy.create_from_description(policy_desc2)
            flaw2 = FlawFactory()
            setattr(flaw2, attribute2, value1)
            sla_context2 = SLAContext(flaw=flaw2)
            sla_context2.sla = policy2.sla

            assert min(sla_context1, sla_context2) is sla_context1

        def test_min_empty(self):
            """
            test that an empty context is never minimal
            """
            policy_desc = {
                "name": "fantastic SLA policy",
                "description": "there is no better",
                "conditions": {},  # this is not valid but OK for this test case
                "sla": {
                    "duration": 5,
                    "start": "creation date",
                    "type": "calendar days",
                },
            }
            policy = SLAPolicy.create_from_description(policy_desc)
            flaw = FlawFactory()
            sla_context1 = SLAContext(flaw=flaw)
            sla_context1.sla = policy.sla

            # an empty SLA context
            sla_context2 = SLAContext()

            assert min(sla_context1, sla_context2) is sla_context1

    class TestTimestamps:
        """
        test SLAContext timestamps computation
        """

        def test_empty(self):
            """
            test that an empty context has None timestamps
            """
            # an empty SLA context
            # with fake flaw entity
            sla_context = SLAContext(flaw="fake")
            assert sla_context.start is None
            assert sla_context.end is None


class TestSLAPolicy:
    """
    test SLAPolicy parsing and computation
    """

    class TestParsing:
        """
        test SLAPolicy definition parsing

        does not include the SLA model parsing test
        which is included in a dedicated test class
        """

        def test_basics(self):
            """
            test parsing of SLAPolicy basics
            """
            policy_desc = {
                "name": "fantastic SLA policy",
                "description": "there is no better",
                "conditions": {},  # this is not valid but OK for this test case
                "sla": {
                    "duration": 5,
                    "start": "unembargo date",
                    "type": "business days",
                },
            }
            policy = SLAPolicy.create_from_description(policy_desc)

            assert policy.name == "fantastic SLA policy"
            assert policy.description == "there is no better"
            # also check that there is some SLA inside
            assert policy.sla.duration == 5

        @pytest.mark.parametrize(
            "definition,expected_affect,expected_flaw,expected_tracker",
            [
                (
                    {
                        "flaw": ["major incident state is approved"],
                    },
                    [],
                    ["major incident state is approved"],
                    [],
                ),
                (
                    {
                        "flaw": [
                            "major incident state is cisa approved",
                            "is not embargoed",
                        ],
                    },
                    [],
                    ["major incident state is cisa approved", "is not embargoed"],
                    [],
                ),
                (
                    {
                        "affect": ["is community"],
                        "flaw": [
                            "major incident state is approved",
                            "is not embargoed",
                        ],
                    },
                    ["is community"],
                    ["major incident state is approved", "is not embargoed"],
                    [],
                ),
                (
                    {
                        "affect": ["is community"],
                        "flaw": [
                            "major incident state is approved",
                            "is not embargoed",
                            "state is not triage",
                        ],
                        "tracker": ["aggregated impact is critical"],
                    },
                    ["is community"],
                    [
                        "major incident state is approved",
                        "is not embargoed",
                        "state is not triage",
                    ],
                    ["aggregated impact is critical"],
                ),
                (
                    {
                        "affect": ["is community"],
                    },
                    ["is community"],
                    [],
                    [],
                ),
                (
                    {
                        "tracker": ["aggregated impact is critical"],
                    },
                    [],
                    [],
                    ["aggregated impact is critical"],
                ),
            ],
        )
        def test_conditions(
            self, definition, expected_affect, expected_flaw, expected_tracker
        ):
            """
            test parsing of SLAPolicy conditions
            """
            policy_desc = {
                "name": "fantastic SLA policy",
                "description": "there is no better",
                "conditions": definition,
                "sla": {
                    "duration": 5,
                    "start": "unembargo date",
                    "type": "business days",
                },
            }
            policy = SLAPolicy.create_from_description(policy_desc)

            # let us only check the conditions by name here
            # checking the whole functionality will be done in other tests
            assert [
                condition.name for condition in policy.conditions.get("affect", [])
            ] == expected_affect
            assert [
                condition.name for condition in policy.conditions.get("flaw", [])
            ] == expected_flaw
            assert [
                condition.name for condition in policy.conditions.get("tracker", [])
            ] == expected_tracker

    class TestConditions:
        """
        test SLAPolicy conditions eveluation
        """

        def test_conditions(self):
            """
            test evaluating of SLAPolicy conditions
            """
            policy_desc = {
                "name": "fantastic SLA policy",
                "description": "there is no better",
                "conditions": {
                    "affect": [
                        "is community",
                    ],
                    "flaw": [
                        "major incident state is approved",
                        "is not embargoed",
                    ],
                    "tracker": [
                        "aggregated impact is moderate",
                    ],
                },
                "sla": {
                    "duration": 5,
                    "start": "unembargo date",
                    "type": "business days",
                },
            }
            policy = SLAPolicy.create_from_description(policy_desc)

            flaw = FlawFactory(
                components=["dnf"],
                embargoed=False,
                major_incident_state=Flaw.FlawMajorIncident.APPROVED,
                impact=Impact.LOW,
            )
            ps_product = PsProductFactory(business_unit="Community")
            ps_module = PsModuleFactory(ps_product=ps_product)
            affect = AffectFactory(
                flaw=flaw,
                affectedness=Affect.AffectAffectedness.AFFECTED,
                resolution=Affect.AffectResolution.DELEGATED,
                ps_module=ps_module.name,
                impact=Impact.MODERATE,
            )
            tracker = TrackerFactory(
                affects=[affect],
                embargoed=flaw.embargoed,
                type=Tracker.BTS2TYPE[ps_module.bts_name],
            )

            # provide SLA context
            assert policy.accepts(
                SLAContext(
                    flaw=flaw,
                    affect=affect,
                    tracker=tracker,
                )
            )

        def test_conditions_multiple_flaws(self):
            """
            test evaluating of SLAPolicy conditions when there are multiple flaws associated
            """
            policy_desc = {
                "name": "fantastic SLA policy",
                "description": "there is no better",
                "conditions": {
                    "affect": [
                        "aggregated impact is moderate",
                        "is community",
                        "ps_component is dnf",
                    ],
                    "flaw": [
                        "major incident state is approved",
                        "is not embargoed",
                    ],
                },
                "sla": {
                    "duration": 5,
                    "start": "unembargo date",
                    "type": "business days",
                },
            }
            policy = SLAPolicy.create_from_description(policy_desc)

            flaw1 = FlawFactory(
                components=["dnf"],
                embargoed=False,
                major_incident_state=Flaw.FlawMajorIncident.APPROVED,
                impact=Impact.LOW,
                title="real flaw",
            )
            flaw2 = FlawFactory(
                components=["ansible"],
                embargoed=flaw1.embargoed,
                major_incident_state=Flaw.FlawMajorIncident.NOVALUE,
                impact=Impact.IMPORTANT,
                title="test",
            )
            ps_product = PsProductFactory(business_unit="Community")
            ps_module = PsModuleFactory(ps_product=ps_product)
            affect1 = AffectFactory(
                flaw=flaw1,
                affectedness=Affect.AffectAffectedness.AFFECTED,
                resolution=Affect.AffectResolution.DELEGATED,
                ps_module=ps_module.name,
                ps_component="dnf",
                impact=Impact.MODERATE,
            )
            affect2 = AffectFactory(
                flaw=flaw2,
                affectedness=Affect.AffectAffectedness.AFFECTED,
                resolution=Affect.AffectResolution.DELEGATED,
                ps_module=ps_module.name,
                ps_component="dnf",
                impact=Impact.LOW,
            )
            tracker = TrackerFactory(
                affects=[affect1, affect2],
                embargoed=flaw1.embargoed,
                type=Tracker.BTS2TYPE[ps_module.bts_name],
            )

            # first flaw context should be accepted
            # because it meets the conditions
            assert policy.accepts(
                SLAContext(
                    flaw=flaw1,
                    affect=affect1,
                    tracker=tracker,
                )
            )
            # second flaw context should not be accepted
            # because it does not meet the conditions
            assert not policy.accepts(
                SLAContext(
                    flaw=flaw2,
                    affect=affect2,
                    tracker=tracker,
                )
            )

    class TestContext:
        """
        test SLAPolicy context determination
        """

        def test_context(self):
            """
            test simple determination of SLAPolicy context
            """
            policy_desc = {
                "name": "fantastic SLA policy",
                "description": "there is no better",
                "conditions": {
                    "flaw": [
                        "is not embargoed",
                    ],
                },
                "sla": {
                    "duration": 5,
                    "start": "unembargo date",
                    "type": "calendar days",
                },
            }
            policy = SLAPolicy.create_from_description(policy_desc)

            flaw = FlawFactory(
                components=["dnf"],
                embargoed=False,
            )
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

            sla_context = policy.context(tracker)
            assert sla_context
            assert sla_context["affect"] == affect
            assert sla_context["flaw"] == flaw
            assert sla_context["tracker"] == tracker
            assert sla_context.sla == policy.sla
            assert sla_context.start == flaw.unembargo_dt
            assert sla_context.end == flaw.unembargo_dt + timedelta(days=5)

        def test_context_multiple_flaws(self):
            """
            test evaluating of SLAPolicy conditions when
            there are multiple accepted flaws associated
            """
            policy_desc = {
                "name": "fantastic SLA policy",
                "description": "there is no better",
                "conditions": {
                    "affect": [
                        "ps_component is dnf",
                    ],
                    "flaw": [
                        "is not embargoed",
                    ],
                },
                "sla": {
                    "duration": 5,
                    "start": "unembargo date",
                    "type": "calendar days",
                },
            }
            policy = SLAPolicy.create_from_description(policy_desc)

            flaw1 = FlawFactory(
                components=["dnf"],
                embargoed=False,
                unembargo_dt=make_aware(datetime(2010, 1, 1)),  # earlier date
            )
            flaw2 = FlawFactory(
                components=["dnf"],
                embargoed=flaw1.embargoed,
                unembargo_dt=make_aware(datetime(2020, 1, 1)),
            )
            ps_module = PsModuleFactory()
            affect1 = AffectFactory(
                flaw=flaw1,
                affectedness=Affect.AffectAffectedness.AFFECTED,
                resolution=Affect.AffectResolution.DELEGATED,
                ps_module=ps_module.name,
                ps_component="dnf",
            )
            affect2 = AffectFactory(
                flaw=flaw2,
                affectedness=Affect.AffectAffectedness.AFFECTED,
                resolution=Affect.AffectResolution.DELEGATED,
                ps_module=ps_module.name,
                ps_component="dnf",
            )
            tracker = TrackerFactory(
                affects=[affect1, affect2],
                embargoed=flaw1.embargoed,
                type=Tracker.BTS2TYPE[ps_module.bts_name],
            )

            # both context are accepted
            assert policy.accepts(
                SLAContext(
                    flaw=flaw1,
                    affect=affect1,
                    tracker=tracker,
                )
            )
            assert policy.accepts(
                SLAContext(
                    flaw=flaw2,
                    affect=affect2,
                    tracker=tracker,
                )
            )

            # but the first one resutls in earliest SLA end
            sla_context = policy.context(tracker)
            assert sla_context
            assert sla_context["affect"] == affect1
            assert sla_context["flaw"] == flaw1
            assert sla_context["tracker"] == tracker
            assert sla_context.sla == policy.sla
            assert sla_context.start == flaw1.unembargo_dt
            assert sla_context.end == flaw1.unembargo_dt + timedelta(days=5)

        def test_policy_not_applicable(self):
            """
            Test that SLA policy does not apply when rhsa_sla_applicable is false
            in the PS update stream.
            """
            policy_desc = {
                "name": "fantastic SLA policy",
                "description": "there is no better",
                "conditions": {
                    "flaw": [
                        "is not embargoed",
                    ],
                },
                "sla": {
                    "duration": 5,
                    "start": "unembargo date",
                    "type": "business days",
                },
            }
            policy = SLAPolicy.create_from_description(policy_desc)

            flaw = FlawFactory(
                embargoed=False,
            )
            ps_module = PsModuleFactory()
            affect = AffectFactory(
                flaw=flaw,
                affectedness=Affect.AffectAffectedness.AFFECTED,
                resolution=Affect.AffectResolution.DELEGATED,
                ps_module=ps_module.name,
            )
            ps_update_stream = PsUpdateStreamFactory(
                ps_module=ps_module, rhsa_sla_applicable=False
            )
            tracker = TrackerFactory(
                affects=[affect],
                embargoed=flaw.embargoed,
                type=Tracker.BTS2TYPE[ps_module.bts_name],
                ps_update_stream=ps_update_stream.name,
            )

            sla_context = policy.context(tracker)
            assert not sla_context
