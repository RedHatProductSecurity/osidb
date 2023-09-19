import random

import pytest
from django.utils import timezone

from apps.osim.models import Check, State, Workflow
from apps.osim.workflow import WorkflowFramework, WorkflowModel
from osidb.models import Affect, Flaw, FlawSource, FlawType, Impact
from osidb.tests.factories import (
    AffectFactory,
    FlawCVSSFactory,
    FlawFactory,
    PackageFactory,
)

pytestmark = pytest.mark.unit


def assert_state_equals(current, expected):
    message = f'flaw classified as {current.name}, expected {expected["name"]}'
    assert current.name == expected["name"], message


def assert_workflow_equals(current, expected):
    message = f"flaw classified in {current.name} workflow, expected {expected.name}"
    assert current.name == expected.name, message


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
        ("has impact", "impact", Impact.MODERATE),
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
    @pytest.mark.parametrize(
        "field,factory",
        [
            ("affects", lambda flaw: AffectFactory(flaw=flaw)),
            ("cvss_scores", lambda flaw: FlawCVSSFactory(flaw=flaw)),
            ("package_versions", lambda flaw: PackageFactory(flaw=flaw)),
        ],
    )
    def test_relational_property(self, field, factory):
        """
        test that properties from a relationship with flaw reject
        an empty list and accept it while having at least one element
        """
        flaw = FlawFactory(source=FlawSource.CVE, embargoed=False)
        check = Check(f"has {field}")
        assert not check(
            flaw
        ), f'check for "{check.name}" should have failed, but passed.'

        factory(flaw)
        assert check(flaw), f'check for "{check.name}" failed.'

    def test_function_value(self):
        """
        test if a function without parameters can be used as condition can be checked
        """
        check = Check("is_major_incident_temp")
        # alias
        check_alias = Check("is major incident")

        flaw = FlawFactory(major_incident_state=Flaw.FlawMajorIncident.APPROVED)
        AffectFactory(flaw=flaw)
        assert check(flaw) and check_alias(flaw), f'check for "{check.name}" failed.'

        flaw.major_incident_state = Flaw.FlawMajorIncident.NOVALUE
        assert not check_alias(flaw) and not check(
            flaw
        ), f'check for "{check.name}" should have failed, but passed.'

    @pytest.mark.parametrize(
        "field",
        [
            "cve_id",
            "cwe_id",
            "created_dt",
            "impact",
            "description",
            "title",
            "summary",
            "cvss3",
            "source",
        ],
    )
    def test_property_positive(self, field):
        """
        test that flaw containing requested properties passes in check
        """
        # most of properties are being auto generated as non-null by factory
        flaw = FlawFactory(cwe_id="CWE-1", summary="random summary")
        check = Check(f"has {field}")

        assert check(flaw), f'check for "{check.name}" failed.'

    @pytest.mark.parametrize(
        "field,novalue",
        [
            ("cve_id", ""),
            ("cwe_id", ""),
            ("created_dt", ""),
            ("impact", Impact.NOVALUE),
            ("description", ""),
            ("title", ""),
            ("summary", ""),
            ("cvss3", ""),
            ("source", ""),
        ],
    )
    def test_property_negative(self, field, novalue):
        """
        test that flaw only passes a a check if it not contains
        an excluded properties
        """
        flaw = FlawFactory()
        setattr(flaw, field, novalue)
        check = Check(f"not {field}")

        assert check(flaw), f'check for "{check.name}" failed.'

    @pytest.mark.parametrize(
        "field,alias",
        [
            ("cve_id", "cve"),
            ("cwe_id", "cwe"),
        ],
    )
    def test_property_alias(self, field, alias):
        """
        test that check can use aliases
        """
        flaw = FlawFactory()
        setattr(flaw, field, "any value")
        check = Check(f"has {alias}")
        assert check(flaw), f'check for "{check.name}" failed.'

        setattr(flaw, field, "")
        assert not check(
            flaw
        ), f'check for "{check.name}" should have failed, but passed.'


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

    def test_requirements(self):
        """test that a state accepts a flaw which satisfies its requirements"""

        requirements = [
            "has cve_id",
            "has impact",
            "has cvss3",
            "not cwe",
            "not description",
            "not title",
        ]
        state = State(
            {
                "name": "random name",
                "requirements": requirements,
            }
        )
        flaw = FlawFactory()
        # fields set outside factory to skip validation
        flaw.cwe_id = ""
        flaw.description = ""
        flaw.title = ""

        assert state.accepts(
            flaw
        ), f'flaw doesn\'t met the requirements "{requirements}"'

        flaw.cwe_id = "CWE-1"
        assert not state.accepts(
            flaw
        ), f'state accepted flaw without the requirements "{requirements}"'

        flaw.cwe_id = ""
        flaw.impact = Impact.NOVALUE
        assert not state.accepts(
            flaw
        ), f'state accepted flaw without the requirements "{requirements}"'


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

    @pytest.mark.parametrize(
        "conditions",
        [
            ["has description"],
            ["has description", "has title"],
            ["not description"],
            ["not description", "not title"],
            ["has description", "not title"],
        ],
    )
    def test_satisfied_conditions(self, conditions):
        """test that a workflow accepts a flaw which satisfies its conditions"""

        workflow = Workflow(
            {
                "name": "random name",
                "description": "random description",
                "priority": 0,
                "conditions": conditions,
                "states": [],  # this is not valid but OK for this test
            }
        )
        flaw = FlawFactory()
        for condition in conditions:
            mode, attr = condition.split(" ", maxsplit=1)
            attr = attr.replace(" ", "_")
            if mode == "has":
                setattr(flaw, attr, "valid value")
            elif mode == "not":
                setattr(flaw, attr, "")

        assert workflow.accepts(
            flaw
        ), f'flaw was rejected by workflow conditions "{conditions}"'

    @pytest.mark.parametrize(
        "conditions",
        [
            ["has description"],
            ["has description", "has title"],
            ["not description"],
            ["not description", "not title"],
            ["has description", "not title"],
        ],
    )
    def test_unsatisfied_conditions(self, conditions):
        """test that a workflow accepts a flaw which satisfies its conditions"""

        workflow = Workflow(
            {
                "name": "random name",
                "description": "random description",
                "priority": 0,
                "conditions": conditions,
                "states": [],  # this is not valid but OK for this test
            }
        )
        flaw = FlawFactory()
        for condition in conditions:
            mode, attr = condition.split(" ", maxsplit=1)
            attr = attr.replace(" ", "_")
            if mode == "has":
                setattr(flaw, attr, "")
            elif mode == "not":
                setattr(flaw, attr, "invalid value in a 'not' condition")

        assert not workflow.accepts(
            flaw
        ), f'flaw was wrongly accepted by workflow conditions "{conditions}"'

        # conditions partially satisfied
        if len(conditions) > 1:
            mode, attr = conditions[0].split(" ", maxsplit=1)
            attr = attr.replace(" ", "_")

            if mode == "has":
                setattr(flaw, attr, "valid value")
            elif mode == "not":
                setattr(flaw, attr, "")
        assert not workflow.accepts(
            flaw
        ), f'flaw was wrongly accepted by workflow conditions "{conditions}"'

    def test_classify(self):
        """test that a flaw is correctly classified in the workflow states"""
        state_new = {
            "name": "new",
            "requirements": [],
        }
        state_first = {"name": "first state", "requirements": ["has description"]}
        state_second = {"name": "second state", "requirements": ["has title"]}

        workflow = Workflow(
            {
                "name": "test workflow",
                "description": "a three step workflow to test classification",
                "priority": 0,
                "conditions": [],
                "states": [state_new, state_first, state_second],
            }
        )
        flaw = Flaw()
        assert_state_equals(workflow.classify(flaw), state_new)

        flaw.description = "valid description"
        assert_state_equals(workflow.classify(flaw), state_first)

        flaw.title = "valid title"
        assert_state_equals(workflow.classify(flaw), state_second)

        # Test that a flaw having a later state requirements
        # does not bypass previous states without requirements
        bypass_flaw = Flaw()
        bypass_flaw.cwe_id = "CWE-1"
        assert_state_equals(workflow.classify(bypass_flaw), state_new)


class TestWorkflowFramework:
    def test_classify_priority(self):
        """
        test that a flaw is always classified in the most prior accepting workflow
        """
        new_low = {
            "name": "new low priority state",
            "requirements": [],
        }
        new_high = {
            "name": "new high priority state",
            "requirements": [],
        }

        workflow_low = Workflow(
            {
                "name": "test zero priority workflow",
                "description": "a test workflow",
                "priority": 0,
                "conditions": [],
                "states": [new_low],
            }
        )
        workflow_high = Workflow(
            {
                "name": "test one priority workflow",
                "description": "another test workflow",
                "priority": 1,
                "conditions": [],
                "states": [new_high],
            }
        )

        workflow_framework = WorkflowFramework()
        workflow_framework.register_workflow(workflow_high)
        workflow_framework.register_workflow(workflow_low)

        flaw = Flaw()
        classified_workflow, classified_state = workflow_framework.classify(flaw)
        assert_workflow_equals(classified_workflow, workflow_high)
        assert_state_equals(classified_state, new_high)

        # register order should not matter
        workflow_framework = WorkflowFramework()
        workflow_framework.register_workflow(workflow_low)
        workflow_framework.register_workflow(workflow_high)

        flaw = Flaw()
        classified_workflow, classified_state = workflow_framework.classify(flaw)
        assert_workflow_equals(classified_workflow, workflow_high)
        assert_state_equals(classified_state, new_high)

    def test_classify_complete(self):
        """test flaw classification in both workflow and state"""
        state_new = {
            "name": WorkflowModel.OSIMState.DRAFT,
            "requirements": [],
        }
        state_first = {
            "name": WorkflowModel.OSIMState.ANALYSIS,
            "requirements": ["has description"],
        }
        state_second = {
            "name": WorkflowModel.OSIMState.DONE,
            "requirements": ["has title"],
        }

        workflow_main = Workflow(
            {
                "name": "main workflow",
                "description": "a three step workflow to test classification",
                "priority": 0,
                "conditions": [],
                "states": [state_new, state_first, state_second],
            }
        )

        state_not_affected = {
            "name": WorkflowModel.OSIMState.REVIEW,
            "requirements": [],
        }

        workflow_reject = Workflow(
            {
                "name": "reject workflow",
                "description": "a worflow for rejected flaws",
                "priority": 1,
                "conditions": ["has affects", "affects notaffected"],
                "states": [state_not_affected],
            }
        )

        workflow_framework = WorkflowFramework()
        # remove yml workflows
        workflow_framework._workflows = []
        workflow_framework.register_workflow(workflow_main)
        workflow_framework.register_workflow(workflow_reject)

        flaw = FlawFactory()
        flaw.description = ""
        flaw.title = ""

        classified_workflow, classified_state = workflow_framework.classify(flaw)
        assert_workflow_equals(classified_workflow, workflow_main)
        assert_state_equals(classified_state, state_new)

        flaw.description = "valid description"
        classified_workflow, classified_state = workflow_framework.classify(flaw)
        assert_state_equals(classified_state, state_first)

        flaw.title = "valid title"
        classified_workflow, classified_state = workflow_framework.classify(flaw)
        assert_state_equals(classified_state, state_second)

        affect = AffectFactory(
            flaw=flaw,
            resolution=Affect.AffectResolution.FIX,
            affectedness=Affect.AffectAffectedness.AFFECTED,
        )

        classified_workflow, classified_state = workflow_framework.classify(flaw)
        assert_workflow_equals(classified_workflow, workflow_main)
        assert_state_equals(classified_state, state_second)

        affect.resolution = Affect.AffectResolution.NOVALUE
        affect.affectedness = Affect.AffectAffectedness.NOTAFFECTED
        affect.save()
        classified_workflow, classified_state = workflow_framework.classify(flaw)
        assert_workflow_equals(classified_workflow, workflow_reject)
        assert_state_equals(classified_state, state_not_affected)


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
                # prevent asigning same workflow depending on order in the framework
                break

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
        workflow_framework._workflows = []

        state_new = State(
            {
                "name": WorkflowModel.OSIMState.DRAFT,
                "requirements": [],
            }
        )
        state_first = State(
            {
                "name": WorkflowModel.OSIMState.ANALYSIS,
                "requirements": ["has description"],
            }
        )
        state_second = State(
            {
                "name": WorkflowModel.OSIMState.DONE,
                "requirements": ["has title"],
            }
        )

        states = [state_new, state_first, state_second]

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
        workflow.states = states
        workflow_framework.register_workflow(workflow)

        # major incident workflow
        workflow = Workflow(
            {
                "name": "major incident workflow",
                "description": "random description",
                "priority": 1,  # is more prior than default one
                "conditions": [
                    "is_major_incident_temp"
                ],  # major incident flaws are classified here
                "states": [],  # this is not valid but OK for this test
            }
        )
        workflow.states = states
        workflow_framework.register_workflow(workflow)

        flaw = FlawFactory(major_incident_state=Flaw.FlawMajorIncident.APPROVED)
        AffectFactory(flaw=flaw)

        assert flaw.classification["workflow"] == "major incident workflow"

        flaw.major_incident_state = Flaw.FlawMajorIncident.NOVALUE
        flaw.adjust_classification()

        assert flaw.classification["workflow"] == "default workflow"

    def test_adjust_no_change(self):
        """test that adjusting classification has no effect without flaw modification"""
        flaw = FlawFactory()  # random flaw
        classification = flaw.classification
        flaw.adjust_classification()
        assert classification == flaw.classification
