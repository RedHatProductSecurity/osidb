"""
OSIM workflow model definitions
"""

from .checks import CheckParser


class Check:
    """
    generic boolean check

    has name and description and most importantly a callable body
    which runs over the given instance and returns true or false result

    the actual code of the body is assigned based on
    what is parsed from the check description
    """

    def __init__(self, check_desc):
        self.name = check_desc
        self.description, self.body = CheckParser.parse(check_desc)

    def __call__(self, instance):
        return bool(self.body(instance))

    def accepts(self, instance):
        """
        alias to check call

        to enable polymorphism with classes implementing accepts method
        """
        return self(instance)


class State:
    """
    workflow state

    has name and a list of requirements - boolean checks
    """

    def __init__(self, state_desc):
        self.name = state_desc["name"]
        self.requirements = [
            Check(requirement_desc) for requirement_desc in state_desc["requirements"]
        ]

    def accepts(self, instance):
        """accepts a given instance if it meets all the requirements"""
        return all(requirement(instance) for requirement in self.requirements)


class Workflow:
    """
    workflow

    has name and description and priority which must be unique among all existing workflows
    has also conditions which is a list of checks and a list of states - order matters

    provides classification of the instance in the proper state
    """

    def __init__(self, workflow_desc):
        self.name = workflow_desc["name"]
        self.description = workflow_desc["description"]
        self.priority = int(workflow_desc["priority"])
        self.conditions = [
            Check(requirement_desc) for requirement_desc in workflow_desc["conditions"]
        ]
        self.states = [State(state_desc) for state_desc in workflow_desc["states"]]

    def __eq__(self, other):
        return self.priority == other.priority

    def __lt__(self, other):
        return self.priority < other.priority

    def accepts(self, instance):
        """accepts the instance if it meets all the conditions"""
        return all(condition(instance) for condition in self.conditions)

    def classify(self, instance):
        """
        classify the instance in the proper workflow state

        the proper state is the last accepting state not preceded by any non-accepting state

        the initial state is required to have the empty requirements
        so there is always an applicable state to classify the instance in
        """
        last = None
        for state in self.states:
            if not state.accepts(instance):
                break
            last = state
        return last
