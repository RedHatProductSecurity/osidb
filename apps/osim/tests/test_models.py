import random

import pytest
from django.utils import timezone

from apps.osim.models import Check, State, Workflow
from apps.osim.workflow import WorkflowFramework, WorkflowModel
from osidb.models import Flaw, FlawImpact, FlawMeta, FlawSource, FlawType
from osidb.tests.factories import AffectFactory, FlawFactory, FlawMetaFactory

pytestmark = pytest.mark.unit


class CheckDescFactory:
    """
    test factory to produce random check descriptions together
    with flaw properties according to the specified conditions
    """

    # TODO embargoed is not model attribute any more but annotation
    # so the embargo related checks currently error out and we need to accout for the change
    PROPERTY_TRUE = [
        ("major_incident", "is_major_incident", True),
        # ("embargoed", "embargoed", True),
    ]
    NOT_PROPERTY_TRUE = [
        ("not major incident", "is_major_incident", False),
        # ("not embargoed", "embargoed", False),
    ]
    HAS_PROPERTY_TRUE = [
        ("has uuid", "uuid", "35d1ad45-0dba-41a3-bad6-5dd36d624ead"),
        ("has cve", "cve_id", "CVE-2020-1234"),
        ("has type", "type", FlawType.VULNERABILITY),
        ("has created_dt", "created_dt", timezone.now()),
        ("has updated_dt", "updated_dt", timezone.now()),
        ("has impact", "impact", FlawImpact.MODERATE),
        ("has title", "title", "random title"),
        ("has description", "description", "random description"),
        ("has summary", "summary", "random summary"),
        ("has statement", "statement", "random statement"),
        ("has cwe", "cwe_id", "CWE-123"),
        ("has unembargo_dt", "unembargo_dt", timezone.now()),
        ("has source", "source", FlawSource.APPLE),
        ("has reported_dt", "reported_dt", timezone.now()),
        ("has cvss2", "cvss2", "5.2/AV:L/AC:H/Au:N/C:P/I:P/A:C"),
        ("has cvss2_score", "cvss2_score", "5.2"),
        ("has cvss3", "cvss3", "6.2/CVSS:3.0/AV:L/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:H"),
        ("has cvss3_score", "cvss3_score", "6.2"),
        ("has is_major_incident", "is_major_incident", False),
    ]
    PROPERTY_FALSE = [
        ("major_incident", "is_major_incident", False),
        # ("embargoed", "embargoed", False),
    ]
    NOT_PROPERTY_FALSE = [
        ("not major incident", "is_major_incident", True),
        # ("not embargoed", "embargoed", True),
    ]
    HAS_PROPERTY_FALSE = [
        ("has summary", "summary", ""),
        ("has statement", "statement", ""),
        ("has cwe", "cwe_id", ""),
        ("has source", "source", ""),
        # ("has reported_dt", "reported_dt", None),
        ("has cvss2", "cvss2", ""),
        ("has cvss2_score", "cvss2_score", None),
        ("has cvss3", "cvss3", ""),
        ("has cvss3_score", "cvss3_score", None),
    ]

    ACCEPTS = {
        "property": PROPERTY_TRUE,
        "not_property": NOT_PROPERTY_TRUE,
        "has_property": HAS_PROPERTY_TRUE,
    }
    REJECTS = {
        "property": PROPERTY_FALSE,
        "not_property": NOT_PROPERTY_FALSE,
        "has_property": HAS_PROPERTY_FALSE,
    }

    @classmethod
    def _merge_dicts(cls, left, right):
        properties = left.copy()
        properties.update(right)
        return properties

    @classmethod
    def _get_universe(cls, accepts=None):
        universe = []

        if accepts is True or accepts is None:
            universe.append(cls.ACCEPTS)
        if accepts is False or accepts is None:
            universe.append(cls.REJECTS)

        return universe

    @classmethod
    def _get_pool(cls, cathegory=None, accepts=None, count=None, exclude=None):
        pool = []
        for domain in cls._get_universe(accepts):
            for domain_cathegory, space in domain.items():
                if cathegory == domain_cathegory or cathegory is None:
                    pool.extend(space)

        return cls._filter_pool(pool, count, exclude)

    @classmethod
    def _filter_pool(cls, pool, count=None, exclude=None):
        # we need to exclude flaw property and not just requirement
        # as some requirements share the flaw properties which could create conflict
        pool = pool if exclude is None else [r for r in pool if r[1] not in exclude]

        count = len(pool) if count is None else count
        count = (
            len(pool) if count > len(pool) else count
        )  # we may run out of possible checks
        return pool if count is None else random.sample(pool, count)

    @classmethod
    def generate(cls, cathegory=None, accepts=None, count=None, exclude=None):
        """
        generates requirements array and flaw properties dictionary based on the set criteria
            - the behavior with unexpected paramenter values is undefined
            - the result length may be less than count if conflicting properties were filtered out
        """
        requirements = []
        flaw_properties = {}
        for requirement, flaw_property, value in cls._get_pool(
            cathegory, accepts, count, exclude
        ):
            # skip conflicting properties
            if flaw_property in flaw_properties:
                continue
            requirements.append(requirement)
            flaw_properties[flaw_property] = value

        flaw_properties = cls._merge_dicts(
            flaw_properties, exclude if exclude is not None else {}
        )
        return requirements, flaw_properties


class StateFactory:
    """
    test factory to produce semi-random states based on set
    properties together with the corresponding flaw properties
    """

    index = 0

    def generate(self, accepts=None, count=0, exclude=None):
        """
        generates state array and flaw properties dictionary based on the set criteria
            - the behavior with unexpected paramenter values is undefined
        """
        states = []
        flaw_properties = {} if exclude is None else exclude

        for _ in range(count):
            requirements, flaw_properties = CheckDescFactory.generate(
                accepts=accepts, count=random.randint(1, 3), exclude=flaw_properties
            )
            states.append(
                State(
                    {
                        "name": WorkflowModel.OSIMState.values[self.index],
                        "requirements": requirements,
                    }
                )
            )
            self.index += 1

        return states, flaw_properties


class TestCheck:
    @pytest.mark.parametrize("cathegory", ["property", "not_property", "has_property"])
    def test_property_positive(self, cathegory):
        """test that property check accepts a flaw with that property being True"""
        flaw_properties = {
            "unembargo_dt": None,
            "embargoed": None,
            "cvss3": "3.7/CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N",
            "title": "EMBARGOED CVE-2022-1234 kernel: some description",
        }
        requirements, flaw_properties = CheckDescFactory.generate(
            cathegory=cathegory, accepts=True, count=1, exclude=flaw_properties
        )
        check_desc = requirements[0]  # one requirement was requested
        check = Check(check_desc)
        flaw = FlawFactory.build(**flaw_properties)

        if (
            "is_major_incident" in flaw_properties
            and flaw_properties["is_major_incident"]
        ):
            flaw.save(raise_validation_error=False)
            AffectFactory(flaw=flaw)
            FlawMetaFactory(
                flaw=flaw,
                type=FlawMeta.FlawMetaType.REQUIRES_SUMMARY,
                meta_attr={"status": "-"},
            )
        flaw.save()
        assert check(
            flaw
        ), f'"{check_desc}" check does not accept a flaw with {flaw_properties}'

    @pytest.mark.parametrize("cathegory", ["property", "not_property", "has_property"])
    def test_property_negative(self, cathegory):
        """test that property check rejects a flaw with that property being False"""
        flaw_properties = {
            "unembargo_dt": None,
            "embargoed": None,
            "cvss3": "3.7/CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N",
            "title": "EMBARGOED CVE-2022-1234 kernel: some description",
        }
        requirements, flaw_properties = CheckDescFactory.generate(
            cathegory=cathegory,
            accepts=False,
            count=1,
            exclude=flaw_properties,
        )

        check_desc = requirements[0]  # one requirement was requested
        check = Check(check_desc)
        flaw = FlawFactory.build(**flaw_properties)

        if flaw.is_major_incident:
            flaw.save(raise_validation_error=False)
            AffectFactory(flaw=flaw)
            FlawMetaFactory(
                flaw=flaw,
                type=FlawMeta.FlawMetaType.REQUIRES_SUMMARY,
                meta_attr={"status": "-"},
            )
        flaw.save()

        assert not check(
            flaw
        ), f'"{check_desc}" check does not reject a flaw with {flaw_properties}'

    @pytest.mark.parametrize("cathegory", ["property", "not_property", "has_property"])
    def test_all_properties_positive(self, cathegory):
        """test all positive properties"""
        flaw_properties = {
            "unembargo_dt": None,
            "embargoed": None,
            "cvss3": "3.7/CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N",
            "title": "EMBARGOED CVE-2022-1234 kernel: some description",
        }
        requirements, flaw_properties = CheckDescFactory.generate(
            cathegory=cathegory, accepts=True, exclude=flaw_properties
        )
        flaw = FlawFactory.build(**flaw_properties)

        if flaw.is_major_incident:
            flaw.save(raise_validation_error=False)
            AffectFactory(flaw=flaw)
            FlawMetaFactory(
                flaw=flaw,
                type=FlawMeta.FlawMetaType.REQUIRES_SUMMARY,
                meta_attr={"status": "-"},
            )
        flaw.save()

        for check_desc in requirements:
            check = Check(check_desc)
            assert check(
                flaw
            ), f'"{check_desc}" check does not accept a flaw with {flaw_properties}'

    @pytest.mark.parametrize("cathegory", ["property", "not_property", "has_property"])
    def test_all_properties_negative(self, cathegory):
        """test all negative properties"""
        flaw_properties = {
            "unembargo_dt": None,
            "embargoed": None,
            "cvss3": "3.7/CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N",
            "title": "EMBARGOED CVE-2022-1234 kernel: some description",
        }
        requirements, flaw_properties = CheckDescFactory.generate(
            cathegory=cathegory, accepts=False, exclude=flaw_properties
        )
        flaw = FlawFactory.build(**flaw_properties)

        if flaw.is_major_incident:
            flaw.save(raise_validation_error=False)
            AffectFactory(flaw=flaw)
            FlawMetaFactory(
                flaw=flaw,
                type=FlawMeta.FlawMetaType.REQUIRES_SUMMARY,
                meta_attr={"status": "-"},
            )
        flaw.save()

        for check_desc in requirements:
            check = Check(check_desc)
            assert not check(
                flaw
            ), f'"{check_desc}" check does not reject a flaw with {flaw_properties}'


class TestState:
    def test_empty_requirements(self):
        """test that a state with empty requirements accepts any flaw"""
        state = State(
            {
                "name": "random name",
                "requirements": [],
            }
        )
        flaw = FlawFactory()  # random flaw
        assert state.accepts(flaw), "state with no requirements rejects a flaw"

    @pytest.mark.parametrize("count", [1, 2, 3, 4, 5])
    def test_satisfied_requirements(self, count):
        """test that a state accepts a flaw which satisfies its requirements"""
        flaw_properties = {
            "unembargo_dt": None,
            "embargoed": None,
            "cvss3": "3.7/CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N",
            "title": "EMBARGOED CVE-2022-1234 kernel: some description",
        }
        requirements, flaw_properties = CheckDescFactory.generate(
            accepts=True, count=count, exclude=flaw_properties
        )
        state = State(
            {
                "name": "random name",
                "requirements": requirements,
            }
        )
        flaw = FlawFactory.build(**flaw_properties)

        if flaw.is_major_incident:
            flaw.save(raise_validation_error=False)
            AffectFactory(flaw=flaw)
            FlawMetaFactory(
                flaw=flaw,
                type=FlawMeta.FlawMetaType.REQUIRES_SUMMARY,
                meta_attr={"status": "-"},
            )
        flaw.save()

        message = (
            f'state with requirements "{requirements}"'
            f"does not accept a flaw with {flaw_properties}"
        )
        assert state.accepts(flaw), message

    @pytest.mark.parametrize(
        "positive,negative", [(0, 1), (1, 1), (7, 1), (0, 5), (3, 3)]
    )
    def test_unsatisfied_requirements(self, positive, negative):
        """test that a state rejects a flaw which does not satisfy its requirements"""
        flaw_properties = {
            "unembargo_dt": None,
            "embargoed": None,
            "cvss3": "3.7/CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N",
            "title": "EMBARGOED CVE-2022-1234 kernel: some description",
        }
        positive_requirements, flaw_properties = CheckDescFactory.generate(
            accepts=True, count=positive, exclude=flaw_properties
        )
        negative_requirements, flaw_properties = CheckDescFactory.generate(
            accepts=False, count=negative, exclude=flaw_properties
        )
        requirements = positive_requirements + negative_requirements
        random.shuffle(requirements)
        state = State(
            {
                "name": "random name",
                "requirements": requirements,
            }
        )
        flaw = FlawFactory.build(**flaw_properties)

        if (
            "is_major_incident" in flaw_properties
            and flaw_properties["is_major_incident"]
        ):
            flaw.save(raise_validation_error=False)
            AffectFactory(flaw=flaw)
            FlawMetaFactory(
                flaw=flaw,
                type=FlawMeta.FlawMetaType.REQUIRES_SUMMARY,
                meta_attr={"status": "-"},
            )
        flaw.save()

        message = (
            f'state with requirements "{requirements}"'
            f"does not reject a flaw with {flaw_properties}"
        )
        assert not state.accepts(flaw), message


class TestWorkflow:
    def test_empty_conditions(self):
        """test that a workflow with empty conditions accepts any flaw"""
        workflow = Workflow(
            {
                "name": "random name",
                "description": "random description",
                "priority": 0,
                "conditions": [],
                "states": [],  # this is not valid but OK for this test
            }
        )
        flaw = FlawFactory()  # random flaw
        assert workflow.accepts(flaw), "workflow with no conditions rejects a flaw"

    @pytest.mark.parametrize("count", [1, 2, 3, 4, 5])
    def test_satisfied_conditions(self, count):
        """test that a workflow accepts a flaw which satisfies its conditions"""
        flaw_properties = {
            "unembargo_dt": None,
            "embargoed": None,
            "cvss3": "3.7/CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N",
            "title": "EMBARGOED CVE-2022-1234 kernel: some description",
        }
        conditions, flaw_properties = CheckDescFactory.generate(
            accepts=True, count=count, exclude=flaw_properties
        )
        workflow = Workflow(
            {
                "name": "random name",
                "description": "random description",
                "priority": 0,
                "conditions": conditions,
                "states": [],  # this is not valid but OK for this test
            }
        )
        flaw = FlawFactory.build(**flaw_properties)

        if flaw.is_major_incident:
            flaw.save(raise_validation_error=False)
            AffectFactory(flaw=flaw)
            FlawMetaFactory(
                flaw=flaw,
                type=FlawMeta.FlawMetaType.REQUIRES_SUMMARY,
                meta_attr={"status": "-"},
            )
        flaw.save()

        message = (
            f'workflow with conditions "{conditions}"'
            f"does not accept a flaw with {flaw_properties}"
        )
        assert workflow.accepts(flaw), message

    @pytest.mark.parametrize(
        "positive,negative", [(0, 1), (1, 1), (7, 1), (0, 5), (3, 3)]
    )
    def test_unsatisfied_conditions(self, positive, negative):
        """test that a workflow rejects a flaw which does not satisfy its conditions"""
        flaw_properties = {
            "unembargo_dt": None,
            "embargoed": None,
            "cvss3": "3.7/CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N",
            "title": "EMBARGOED CVE-2022-1234 kernel: some description",
        }
        positive_conditions, flaw_properties = CheckDescFactory.generate(
            accepts=True, count=positive, exclude=flaw_properties
        )
        negative_conditions, flaw_properties = CheckDescFactory.generate(
            accepts=False, count=negative, exclude=flaw_properties
        )
        conditions = positive_conditions + negative_conditions
        random.shuffle(conditions)
        workflow = Workflow(
            {
                "name": "random name",
                "description": "random description",
                "priority": 0,
                "conditions": conditions,
                "states": [],  # this is not valid but OK for this test
            }
        )
        flaw = FlawFactory.build(**flaw_properties)

        if (
            "is_major_incident" in flaw_properties
            and flaw_properties["is_major_incident"]
        ):
            flaw.save(raise_validation_error=False)
            AffectFactory(flaw=flaw)
            FlawMetaFactory(
                flaw=flaw,
                type=FlawMeta.FlawMetaType.REQUIRES_SUMMARY,
                meta_attr={"status": "-"},
            )
        flaw.save()
        message = (
            f'workflow with conditions "{conditions}"'
            f"does not reject a flaw with {flaw_properties}"
        )
        assert not workflow.accepts(flaw), message

    @pytest.mark.parametrize("count1,count2", [(1, 1), (2, 2), (3, 1), (1, 4)])
    def test_classify(self, count1, count2):
        """test that a flaw is correctly classified in the workflow states"""
        flaw_properties = {
            "unembargo_dt": None,
            "embargoed": None,
            "cvss3": "3.7/CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N",
            "title": "EMBARGOED CVE-2022-1234 kernel: some description",
        }
        state_factory = StateFactory()
        accepting_states, flaw_properties = state_factory.generate(
            accepts=True, count=count1, exclude=flaw_properties
        )
        rejecting_states, flaw_properties = state_factory.generate(
            accepts=False, count=1, exclude=flaw_properties
        )
        random_states, flaw_properties = state_factory.generate(
            count=count2, exclude=flaw_properties
        )

        classify_in = accepting_states[-1]

        workflow = Workflow(
            {
                "name": "random name",
                "description": "random description",
                "priority": 0,
                "conditions": [],
                "states": [],  # this is not valid but OK for this test
            }
        )
        workflow.states = accepting_states + rejecting_states + random_states
        flaw = FlawFactory.build(**flaw_properties)

        if (
            "is_major_incident" in flaw_properties
            and flaw_properties["is_major_incident"]
        ):
            flaw.save(raise_validation_error=False)
            AffectFactory(flaw=flaw)
            FlawMetaFactory(
                flaw=flaw,
                type=FlawMeta.FlawMetaType.REQUIRES_SUMMARY,
                meta_attr={"status": "-"},
            )
        flaw.save()

        message = (
            "flaw in workflow classification failure - was classified in state "
            f'"{workflow.classify(flaw).name}" instead of "{classify_in.name}"'
        )
        assert workflow.classify(flaw).name == classify_in.name, message

    @pytest.mark.parametrize("count", [1, 2, 3, 4, 5])
    def test_classify_default_state(self, count):
        """
        test that a flaw is always classified in some state when a workflow has the default state
        """
        random_states, _ = StateFactory().generate(count=count)
        random_states[0].requirements = []  # default state
        workflow = Workflow(
            {
                "name": "random name",
                "description": "random description",
                "priority": 0,
                "conditions": [],
                "states": [],  # this is not valid but OK for this test
            }
        )
        workflow.states = random_states
        workflow_framework = WorkflowFramework()
        workflow_framework.register_workflow(workflow)
        flaw = FlawFactory()  # random flaw

        message = (
            "flaw was not classified in any state despite the default state exists"
        )
        assert workflow.classify(flaw) is not None, message


class TestWorkflowFramework:
    @pytest.mark.parametrize("count", [0, 1, 2, 3, 4, 5])
    def test_classify_default_state(self, count):
        """
        test that a flaw is always classified in some workflow when the default workflow exists
        """
        random_states, _ = StateFactory().generate(count=random.randint(1, 3))
        random_states[0].requirements = []  # default state
        default_workflow = Workflow(
            {
                "name": "random name",
                "description": "random description",
                "priority": 0,
                "conditions": [],  # default workflow with empty conditions
                "states": [],  # this is not valid but OK for this test
            }
        )
        default_workflow.states = random_states
        workflow_framework = WorkflowFramework()
        workflow_framework.register_workflow(default_workflow)

        for index in range(count):
            state_factory = StateFactory()
            random_states, _ = state_factory.generate(count=random.randint(1, 3))
            random_states[0].requirements = []  # default state
            conditions, _ = CheckDescFactory.generate()
            workflow = Workflow(
                {
                    "name": f"random name {index}",
                    "description": "random description",
                    "priority": index + 1,
                    "conditions": conditions,  # random workflow conditions
                    "states": [],  # this is not valid but OK for this test
                }
            )
            workflow.states = random_states
            workflow_framework.register_workflow(workflow)

        flaw = FlawFactory()  # random flaw

        message = "flaw was not classified in any workflow despite the default workflow exists"
        assert workflow_framework.classify(flaw, state=False) is not None, message

    @pytest.mark.parametrize("count", [1, 2, 3, 4, 5])
    def test_classify_priority(self, count):
        """
        test that a flaw is always classified in the most prior accepting workflow
        """
        workflow_framework = WorkflowFramework()

        random_states, _ = StateFactory().generate(count=1)
        random_states[0].requirements = []  # default state

        for index in range(count):
            workflow = Workflow(
                {
                    "name": f"random name {index}",
                    "description": "random description",
                    "priority": index + 1,
                    "conditions": [],
                    "states": [],  # this is not valid but OK for this test
                }
            )
            workflow.states = random_states
            workflow_framework.register_workflow(workflow)

        flaw = FlawFactory()  # random flaw

        message = (
            "flaw was classified in workflow with priority "
            f"{workflow_framework.classify(flaw, state=False).priority} "
            f"despite the most prior accepting workflow has priority {count}"
        )
        assert workflow_framework.classify(flaw, state=False).priority == count, message

    @pytest.mark.parametrize(
        "workflows,workflow_name,state_name",
        [
            (
                [
                    ("default", 0, True, 1),
                ],
                "default",
                "DRAFT",
            ),
            (
                [
                    ("another", 1, True, 2),
                    ("default", 0, True, 1),
                ],
                "another",
                "NEW",
            ),
            (
                [
                    ("another", 1, False, 1),
                    ("default", 0, True, 3),
                ],
                "default",
                "ANALYSIS",
            ),
            (
                [
                    ("first", 2, False, 2),
                    ("another", 1, True, 1),
                    ("default", 0, True, 2),
                ],
                "another",
                "DRAFT",
            ),
            # TODO this test case occasionally generates so complex workflows
            # that we are running out of flaw properties which results in empty
            # state requirements so they accept flaw instead of rejecting
            # - enable again when we have more flaw properties or this is refactored
            # (
            #     [
            #         ("first", 3, False, 1),
            #         ("better", 2, False, 1),
            #         ("another", 1, True, 2),
            #         ("default", 0, True, 1),
            #     ],
            #     "another",
            #     "NEW",
            # ),
        ],
    )
    def test_classify_complete(self, workflows, workflow_name, state_name):
        """test flaw classification in both workflow and state"""
        workflow_framework = WorkflowFramework()

        flaw_properties = {
            "unembargo_dt": None,
            "embargoed": None,
            "cvss3": "3.7/CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N",
            "title": "EMBARGOED CVE-2022-1234 kernel: some description",
        }

        for name, priority, accepting, accepting_states in workflows:
            workflow = Workflow(
                {
                    "name": name,
                    "description": "random description",
                    "priority": priority,
                    "conditions": [],
                    "states": [],  # this is not valid but OK for this test
                }
            )
            # create conditions
            requirements, flaw_properties = CheckDescFactory.generate(
                accepts=accepting, count=1, exclude=flaw_properties
            )
            workflow.conditions = [Check(check_dest) for check_dest in requirements]
            # create states with one additional rejecting
            state_factory = StateFactory()
            a_states, flaw_properties = state_factory.generate(
                accepts=True, count=accepting_states, exclude=flaw_properties
            )
            r_states, flaw_properties = state_factory.generate(
                accepts=False, count=1, exclude=flaw_properties
            )
            workflow.states = a_states + r_states
            # register workflow in the workflow framework
            workflow_framework.register_workflow(workflow)

        flaw = FlawFactory.build(**flaw_properties)

        if flaw.is_major_incident:
            flaw.save(raise_validation_error=False)
            AffectFactory(flaw=flaw)
            FlawMetaFactory(
                flaw=flaw,
                type=FlawMeta.FlawMetaType.REQUIRES_SUMMARY,
                meta_attr={"status": "-"},
            )
        flaw.save()

        classified_workflow, classified_state = workflow_framework.classify(flaw)
        message = (
            f"flaw was classified in workflow to {classified_workflow.name}:{classified_state.name}"
            f" but the expected classification was {workflow_name}:{state_name}"
        )
        assert (
            classified_workflow.name == workflow_name
            and classified_state.name == state_name
        ), message


class TestFlaw:
    def test_init(self):
        """test that flaw gets workflow:state assigned on creation"""
        flaw = Flaw()
        assert flaw.osim_workflow
        assert flaw.osim_state

    def test_classification(self):
        """test flaw classification property"""
        flaw = Flaw()

        # stored classification
        assert flaw.osim_workflow == flaw.classification["workflow"]
        assert flaw.osim_state == flaw.classification["state"]
        # computed classification
        old_computed_workflow = flaw.classify()["workflow"]
        old_computed_state = flaw.classify()["state"]
        assert flaw.osim_workflow == old_computed_workflow
        assert flaw.osim_state == old_computed_state

        # assing new and different classification
        for workflow in WorkflowFramework().workflows:
            if workflow.name != flaw.osim_workflow:
                for state in workflow.states:
                    if state.name != flaw.osim_state:
                        new_stored_workflow = workflow.name
                        new_stored_state = state.name
                        flaw.classification = {
                            "workflow": new_stored_workflow,
                            "state": new_stored_state,
                        }

        # stored classification has changed
        assert flaw.osim_workflow == new_stored_workflow
        assert flaw.osim_workflow == flaw.classification["workflow"]
        assert flaw.osim_state == new_stored_state
        assert flaw.osim_state == flaw.classification["state"]
        # computed classification has not changed
        new_computed_workflow = flaw.classify()["workflow"]
        new_computed_state = flaw.classify()["state"]
        assert old_computed_workflow == new_computed_workflow
        assert old_computed_state == new_computed_state
        assert flaw.osim_workflow != new_computed_workflow
        assert flaw.osim_state != new_computed_state

    def test_adjust(self):
        """test flaw classification adjustion after metadata change"""
        workflow_framework = WorkflowFramework()
        random_states, _ = StateFactory().generate(count=1)
        random_states[0].requirements = []  # default state

        # initialize default workflow first so there is
        # always some workflow to classify the flaw in
        workflow = Workflow(
            {
                "name": "default workflow",
                "description": "random description",
                "priority": 0,
                "conditions": [],
                "states": [],  # this is not valid but OK for this test
            }
        )
        workflow.states = random_states
        workflow_framework.register_workflow(workflow)

        # major incident workflow
        workflow = Workflow(
            {
                "name": "major incident workflow",
                "description": "random description",
                "priority": 1,  # is more prior than default one
                "conditions": [
                    "major_incident"
                ],  # major incident flaws are classified here
                "states": [],  # this is not valid but OK for this test
            }
        )
        workflow.states = random_states
        workflow_framework.register_workflow(workflow)

        flaw = FlawFactory.build(is_major_incident=True)
        flaw.save(raise_validation_error=False)

        AffectFactory(flaw=flaw)
        FlawMetaFactory(
            flaw=flaw,
            type=FlawMeta.FlawMetaType.REQUIRES_SUMMARY,
            meta_attr={"status": "-"},
        )

        assert flaw.classification == {
            "workflow": "major incident workflow",
            "state": "DRAFT",
        }

        flaw.is_major_incident = False
        flaw.adjust_classification()
        assert flaw.classification == {
            "workflow": "default workflow",
            "state": "DRAFT",
        }

        # also test that adjust operation is idempotent
        flaw.adjust_classification()
        assert flaw.classification == {
            "workflow": "default workflow",
            "state": "DRAFT",
        }

    def test_adjust_no_change(self):
        """test that adjusting classification has no effect without flaw modification"""
        flaw = FlawFactory()  # random flaw
        classification = flaw.classification
        flaw.adjust_classification()
        assert classification == flaw.classification
