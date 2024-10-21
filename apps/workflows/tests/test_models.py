import pytest

from apps.workflows.exceptions import LastStateException, MissingRequirementsException
from apps.workflows.models import Check, State, Workflow
from apps.workflows.workflow import WorkflowFramework, WorkflowModel
from osidb.models import Affect, Flaw, FlawReference, FlawSource, Impact, Tracker
from osidb.tests.factories import (
    AffectFactory,
    FlawCVSSFactory,
    FlawFactory,
    FlawReferenceFactory,
    PackageFactory,
    PsModuleFactory,
    PsUpdateStreamFactory,
    TrackerFactory,
)

pytestmark = pytest.mark.unit


def assert_state_equals(current, expected):
    message = f'flaw classified as {current.name}, expected {expected["name"]}'
    assert current.name == expected["name"], message


def assert_workflow_equals(current, expected):
    message = f"flaw classified in {current.name} workflow, expected {expected.name}"
    assert current.name == expected.name, message


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

    @pytest.mark.parametrize(
        "field",
        [
            "cve_id",
            "cwe_id",
            "created_dt",
            "impact",
            "comment_zero",
            "title",
            "cve_description",
            "source",
        ],
    )
    def test_property_positive(self, field):
        """
        test that flaw containing requested properties passes in check
        """
        # most of properties are being auto generated as non-null by factory
        flaw = FlawFactory(cwe_id="CWE-1", cve_description="random cve_description")
        check = Check(f"has {field}")

        assert check(flaw), f'check for "{check.name}" failed.'

    @pytest.mark.parametrize(
        "field,novalue",
        [
            ("cve_id", ""),
            ("cwe_id", ""),
            ("created_dt", ""),
            ("impact", Impact.NOVALUE),
            ("comment_zero", ""),
            ("title", ""),
            ("cve_description", ""),
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

    @pytest.mark.parametrize(
        "attribute,value,check_desc",
        [
            ("cve_id", "CVE-2000-12345", "CVE is CVE-2000-12345"),
            ("cwe_id", "CWE-100", "CWE is CWE-100"),
            ("impact", Impact.CRITICAL, "impact is critical"),
            ("source", FlawSource.CUSTOMER, "source is customer"),
            ("title", "whatever", "title is whatever"),
        ],
    )
    def test_equals(self, attribute, value, check_desc):
        """
        test equality check parsing and resolution
        """
        flaw = FlawFactory()
        setattr(flaw, attribute, value)
        check = Check(check_desc)

        assert check.name == check_desc
        # here we do a case insensitive check as there is
        # a different case handling for the text choices
        assert (
            check.description.lower()
            == f"check that Flaw attribute {attribute} has a value equal to {value}".lower()
        )
        assert check(flaw), f"Check failed: {check.name}"

    def test_equals_failed(self):
        """
        test that equality check fails with unexpected value
        """
        check = Check("cwe is CWE-99")
        assert not check(
            FlawFactory(cwe_id="CWE-100")
        ), f'check for "{check.name}" should have failed, but passed.'

    def test_equals_text_choices_property(self):
        """
        test comparison check parsing and resolution
        of the property returning TextChoices values
        """
        ps_module = PsModuleFactory(bts_name="bugzilla")
        flaw = FlawFactory(embargoed=False, impact=Impact.LOW)
        affect = AffectFactory(
            flaw=flaw,
            impact=None,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_module=ps_module.name,
        )
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)
        tracker = TrackerFactory(
            affects=[affect],
            embargoed=False,
            ps_update_stream=ps_update_stream.name,
            type=Tracker.TrackerType.BUGZILLA,
        )

        check = Check("aggregated impact is low", cls=Tracker)
        assert check(tracker), f"Check failed: {check.name}"

    @pytest.mark.parametrize(
        "attribute,value,not_value,check_desc",
        [
            ("cve_id", "CVE-2000-12345", "CVE-2000-3000", "CVE is not CVE-2000-3000"),
            ("cwe_id", "CWE-100", "CWE-200", "CWE is not CWE-200"),
            ("impact", Impact.CRITICAL, "low", "impact is not low"),
            ("source", FlawSource.CUSTOMER, "internet", "source is not internet"),
            ("title", "whatever", "banana", "title is not banana"),
        ],
    )
    def test_not_equals(self, attribute, value, not_value, check_desc):
        """
        test negative equality check parsing and resolution
        """
        flaw = FlawFactory()
        setattr(flaw, attribute, value)
        check = Check(check_desc)

        assert check.name == check_desc
        # here we do a case insensitive check as there is
        # a different case handling for the text choices
        assert (
            check.description.lower()
            == f"negative of: check that Flaw attribute {attribute} has a value equal to {not_value}".lower()
        )
        assert check(flaw), f"Check failed: {check.name}"

    def test_not_equals_failed(self):
        """
        test that negative equality check fails with expected value
        """
        check = Check("cwe not is CWE-100")
        assert not check(
            FlawFactory(cwe_id="CWE-100")
        ), f'check for "{check.name}" should have failed, but passed.'

    @pytest.mark.parametrize(
        "cls,factory,field,value",
        [
            (Affect, AffectFactory, "impact", Impact.CRITICAL),
            (Flaw, FlawFactory, "impact", Impact.CRITICAL),
            (FlawReference, FlawReferenceFactory, "url", "http://example.com"),
            # we should be theoretically able to apply this to an arbitrary model
            # class so let us test just a few of them and assume it generally works
        ],
    )
    def test_parametrized_model(self, cls, factory, field, value):
        """
        test that check model parametrization works correctly
        """
        instance = factory()
        setattr(instance, field, value)
        # non-emptyness check is very simple to define
        # and it is enough here to use any type of check
        check = Check(f"has {field}", cls)

        assert check.name == f"has {field}"
        assert (
            check.description
            == f"check that {cls.__name__} attribute {field} has a value set"
        )
        assert check(instance), f"Check failed: {check.name}"

    @pytest.mark.parametrize(
        "affectedness,resolution,trackers_required",
        [
            (
                Affect.AffectAffectedness.NEW,
                Affect.AffectResolution.NOVALUE,
                True,
            ),
            (
                Affect.AffectAffectedness.NEW,
                Affect.AffectResolution.WONTFIX,
                False,
            ),
            (
                Affect.AffectAffectedness.NEW,
                Affect.AffectResolution.DEFER,
                False,
            ),
            (
                Affect.AffectAffectedness.NEW,
                Affect.AffectResolution.OOSS,
                False,
            ),
            (
                Affect.AffectAffectedness.AFFECTED,
                Affect.AffectResolution.DELEGATED,
                True,
            ),
            (
                Affect.AffectAffectedness.AFFECTED,
                Affect.AffectResolution.WONTFIX,
                False,
            ),
            (
                Affect.AffectAffectedness.AFFECTED,
                Affect.AffectResolution.DEFER,
                False,
            ),
            (
                Affect.AffectAffectedness.AFFECTED,
                Affect.AffectResolution.OOSS,
                False,
            ),
            (
                Affect.AffectAffectedness.NOTAFFECTED,
                Affect.AffectResolution.NOVALUE,
                False,
            ),
        ],
    )
    def test_has_trackers(self, affectedness, resolution, trackers_required):
        """
        test that the check of the filed trackers works correctly
        """
        flaw = FlawFactory()

        check = Check("has trackers", Flaw)
        assert check.name == "has trackers"
        # the auto-generated description is
        # actually not great for this case
        assert check.description == (
            "check that all affects in\n"
            "NEW:NOVALUE or AFFECTED:DELEGATED\n"
            "have associated trackers filed"
        )
        # with no affects there is nothing which should have trackers
        assert check(flaw), f"Check failed: {check.name}"

        affect = AffectFactory(
            flaw=flaw,
            impact=Impact.LOW,
            affectedness=affectedness,
            resolution=resolution,
        )

        if not trackers_required:
            assert check(flaw)

        else:
            assert not check(flaw)
            tracker = TrackerFactory.build()
            tracker.save(raise_validation_error=False)
            tracker.affects.add(affect)
            assert check(flaw)


class TestState:
    def test_empty_requirements(self):
        """test that a state with empty requirements accepts any flaw"""
        state = State(
            {
                "name": "random name",
                "requirements": [],
                "jira_state": "New",
                "jira_resolution": None,
            }
        )
        flaw = FlawFactory()  # random flaw
        assert state.accepts(flaw), "state with no requirements rejects a flaw"

    def test_requirements(self):
        """test that a state accepts a flaw which satisfies its requirements"""

        requirements = [
            "has cve_id",
            "has impact",
            "not cwe",
            "not comment_zero",
            "not title",
        ]
        state = State(
            {
                "name": "random name",
                "requirements": requirements,
                "jira_state": "To do",
                "jira_resolution": None,
            }
        )
        flaw = FlawFactory()
        # fields set outside factory to skip validation
        flaw.cwe_id = ""
        flaw.comment_zero = ""
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
            ["has comment_zero"],
            ["has comment_zero", "has title"],
            ["not comment_zero"],
            ["not comment_zero", "not title"],
            ["has comment_zero", "not title"],
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
            ["has comment_zero"],
            ["has comment_zero", "has title"],
            ["not comment_zero"],
            ["not comment_zero", "not title"],
            ["has comment_zero", "not title"],
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
            "jira_state": "New",
            "jira_resolution": None,
        }
        state_first = {
            "name": "first state",
            "requirements": ["has comment_zero"],
            "jira_state": "To Do",
            "jira_resolution": None,
        }
        state_second = {
            "name": "second state",
            "requirements": ["has title"],
            "jira_state": "In Progress",
            "jira_resolution": None,
        }

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

        flaw.comment_zero = "valid comment_zero"
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
            "jira_state": "New",
            "jira_resolution": None,
        }
        new_high = {
            "name": "new high priority state",
            "requirements": [],
            "jira_state": "To Do",
            "jira_resolution": None,
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
            "name": WorkflowModel.WorkflowState.NEW,
            "requirements": [],
            "jira_state": "New",
            "jira_resolution": None,
        }
        state_first = {
            "name": WorkflowModel.WorkflowState.TRIAGE,
            "requirements": ["has comment_zero"],
            "jira_state": "To Do",
            "jira_resolution": None,
        }
        state_second = {
            "name": WorkflowModel.WorkflowState.DONE,
            "requirements": ["has title"],
            "jira_state": "Refinement",
            "jira_resolution": None,
        }

        workflow_main = Workflow(
            {
                "name": "DEFAULT",
                "description": "a three step workflow to test classification",
                "priority": 0,
                "conditions": [],
                "states": [state_new, state_first, state_second],
            }
        )

        state_not_affected = {
            "name": WorkflowModel.WorkflowState.REJECTED,
            "requirements": [],
            "jira_state": "Done",
            "jira_resolution": "Won't Do",
        }

        workflow_reject = Workflow(
            {
                "name": "REJECT",
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
        flaw.comment_zero = ""
        flaw.title = ""

        classified_workflow, classified_state = workflow_framework.classify(flaw)
        assert_workflow_equals(classified_workflow, workflow_main)
        assert_state_equals(classified_state, state_new)

        flaw.comment_zero = "valid comment_zero"
        classified_workflow, classified_state = workflow_framework.classify(flaw)
        assert_state_equals(classified_state, state_first)

        flaw.title = "valid title"
        classified_workflow, classified_state = workflow_framework.classify(flaw)
        assert_state_equals(classified_state, state_second)

        affect = AffectFactory(
            flaw=flaw,
            resolution=Affect.AffectResolution.DELEGATED,
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
    @pytest.mark.enable_signals
    def test_init(self):
        """test that flaw gets workflow:state assigned on creation"""
        flaw = FlawFactory()
        assert flaw.workflow_name
        assert flaw.workflow_state == WorkflowModel.WorkflowState.NOVALUE

    @pytest.mark.enable_signals
    def test_adjust(self):
        """test flaw classification adjustion after metadata change"""
        workflow_framework = WorkflowFramework()
        workflow_framework._workflows = []

        state_new = State(
            {
                "name": WorkflowModel.WorkflowState.NEW,
                "jira_state": "New",
                "jira_resolution": None,
                "requirements": [],
            }
        )
        state_first = State(
            {
                "name": WorkflowModel.WorkflowState.TRIAGE,
                "jira_state": "To Do",
                "jira_resolution": None,
                "requirements": ["has comment_zero"],
            }
        )
        state_second = State(
            {
                "name": WorkflowModel.WorkflowState.DONE,
                "jira_state": "In Progress",
                "jira_resolution": None,
                "requirements": ["has title"],
            }
        )

        states = [state_new, state_first, state_second]

        # initialize default workflow first so there is
        # always some workflow to classify the flaw in
        workflow = Workflow(
            {
                "name": "DEFAULT",
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
                "name": "MAJOR_INCIDENT",
                "description": "random description",
                "priority": 1,  # is more prior than default one
                "conditions": [
                    "major_incident_state_is_approved"
                ],  # major incident flaws are classified here
                "states": [],  # this is not valid but OK for this test
            }
        )
        workflow.states = states
        workflow_framework.register_workflow(workflow)

        flaw = FlawFactory(major_incident_state=Flaw.FlawMajorIncident.APPROVED)
        AffectFactory(flaw=flaw)
        flaw.adjust_classification()

        assert flaw.classification["workflow"] == "MAJOR_INCIDENT"

        flaw.major_incident_state = Flaw.FlawMajorIncident.NOVALUE
        flaw.adjust_classification()

        assert flaw.classification["workflow"] == "DEFAULT"

    @pytest.mark.enable_signals
    def test_adjust_no_change(self):
        """test that adjusting classification has no effect without flaw modification"""
        flaw = FlawFactory(
            workflow_state=WorkflowModel.WorkflowState.NEW
        )  # random flaw
        classification = flaw.classification
        flaw.adjust_classification()
        assert classification == flaw.classification

    @pytest.mark.enable_signals
    def test_promote(self):
        """test flaw state promotion after data change"""
        workflow_framework = WorkflowFramework()
        workflow_framework._workflows = []

        state_new = {
            "name": WorkflowModel.WorkflowState.NEW,
            "requirements": [],
            "jira_state": "New",
            "jira_resolution": None,
        }

        state_first = {
            "name": WorkflowModel.WorkflowState.SECONDARY_ASSESSMENT,
            "requirements": ["has cwe"],
            "jira_state": "To Do",
            "jira_resolution": None,
        }

        state_second = {
            "name": WorkflowModel.WorkflowState.DONE,
            "requirements": ["has cve_description"],
            "jira_state": "Refinement",
            "jira_resolution": None,
        }

        workflow = Workflow(
            {
                "name": "DEFAULT",
                "description": "random description",
                "priority": 0,
                "conditions": [],
                "states": [state_new, state_first, state_second],
            }
        )
        workflow_framework.register_workflow(workflow)

        flaw = FlawFactory(
            cwe_id="",
            cve_description="",
            workflow_state=WorkflowModel.WorkflowState.NEW,
        )
        AffectFactory(flaw=flaw)

        assert flaw.classification["workflow"] == "DEFAULT"
        assert flaw.classification["state"] == WorkflowModel.WorkflowState.NEW

        with pytest.raises(MissingRequirementsException, match="has cwe"):
            flaw.promote()
        assert flaw.classification["state"] == WorkflowModel.WorkflowState.NEW

        flaw.cwe_id = "CWE-1"
        assert flaw.promote() is None
        assert (
            flaw.classification["state"]
            == WorkflowModel.WorkflowState.SECONDARY_ASSESSMENT
        )

        with pytest.raises(MissingRequirementsException, match="has cve_description"):
            flaw.promote()
        assert (
            flaw.classification["state"]
            == WorkflowModel.WorkflowState.SECONDARY_ASSESSMENT
        )

        flaw.cve_description = "valid cve_description"
        assert flaw.promote() is None
        assert flaw.classification["state"] == WorkflowModel.WorkflowState.DONE

        with pytest.raises(LastStateException):
            flaw.promote()
