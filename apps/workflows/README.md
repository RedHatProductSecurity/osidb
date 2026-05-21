# Workflow Framework

The workflow framework defines the consecutive phases a flaw goes through to
get fully processed. A classification consisting of a *workflow* and *state* is
automatically derived from the flaw's data on every save, describing its
current progress without requiring any manual state transitions.

## Design Philosophy

The central principle is that **classification is a pure function of flaw data**.
A flaw's workflow and state are not independent attributes to be set manually;
they are derived values, computed automatically from the flaw's current data on
every save.

This principle has three consequences:

1. **Automatic classification.** When a flaw is saved, the framework evaluates
   which workflow applies and how far through that workflow's states the flaw
   can progress. No human action is needed to advance or revert a flaw --
   changing the underlying data is sufficient.

2. **No circular dependencies.** Because classification is derived from data,
   the classification itself must never be an input to its own computation.
   External systems (Jira) receive the computed classification; they never
   dictate it back.

3. **Determinism.** Given the same flaw data, the framework must always produce
   the same classification. There is no hidden state, no history dependence, no
   ordering sensitivity.

### What classification is NOT

Classification is not a user action. A user changes flaw data (assigns an
owner, sets an impact, creates affects, files trackers, ...), and the framework
automatically recognizes that the flaw has reached the next state. The workflow
framework observes data; it does not create it.

## Architecture

### Workflow Definitions (YAML)

Workflows are defined in YAML files under `apps/workflows/workflows/` - TODO
move the workflow definitions to PS constants. Each workflow specifies:

- **name** -- identifier (e.g. `DEFAULT`, `REJECTED`)
- **priority** -- integer; higher priority workflows are evaluated first
- **conditions** -- checks the flaw must satisfy for this workflow to apply;
  empty conditions mean the workflow is unconditional (a catch-all)
- **states** -- ordered list; each state has a name and a list of requirements

### Workflow Selection

`WorkflowFramework.classify()` iterates workflows sorted by descending
priority. The first workflow whose conditions all pass is selected. Because the
`DEFAULT` workflow has empty conditions, it serves as the universal fallback.

### State Classification Algorithm

Within the selected workflow, states are evaluated in order by
`Workflow.classify()` (`apps/workflows/models.py`):

```
last_accepting = None
for state in workflow.states:
    if state does not accept the flaw:
        break
    last_accepting = state
return last_accepting
```

The flaw is classified in the **last accepting state not preceded by any
non-accepting state**. The scan stops at the first failure. This means:

- The initial state (e.g. `NEW`) must have empty requirements so that every
  flaw is accepted into at least the first state.
- Requirements are **cumulative by construction**: reaching state N requires
  that the requirements of all states 1 through N are satisfied, because the
  scan would have stopped at the first non-accepting state.

### Cumulative Requirements

This property is fundamental. To reach state N, a flaw must satisfy the
requirements of **all** states 1 through N. This is not enforced by checking
all prior states explicitly -- it is a natural consequence of the linear scan
algorithm. The algorithm breaks at the first non-accepting state, so it is
impossible to "skip over" an unsatisfied state.

If a requirement that was fulfilled in a prior state becomes unfulfilled (e.g.
owner is cleared), the flaw automatically regresses to the last state whose
requirements are still fully met. No manual action is needed.

## Automatic Classification

### Signal-Driven Classification

Classification runs on every flaw save via a Django `pre_save` signal.
The signal calls `adjust_classification(save=False)` which computes `classify()`
and stores the result on the instance before it reaches the database.

The `task_key` guard ensures that only flaws with a Jira task are classified.
Flaws without a task (legacy flaws) keep empty workflow fields.

### Idempotency

Because `classify()` is a pure function of flaw data, calling
`adjust_classification()` multiple times with the same data produces the same
result. There is no risk of double-promoting or oscillating states.

## DEFAULT Workflow Requirements

### Current State (Stripped - TODO enrich)

The current YAML definitions have been stripped of most requirements because
people working with manual transitions found them annoying:

| State | Current Requirements |
|---|---|
| NEW | (none) |
| TRIAGE | has owner |
| PRE_SECONDARY_ASSESSMENT | has source, has title |
| SECONDARY_ASSESSMENT | has owner |
| DONE | OR(has trackers, impact is low, impact is moderate) |

Notable: `has affects` was commented out from PRE_SECONDARY_ASSESSMENT, and
`has impact` was never a requirement.

### Requirement vs. Validation

Not every data constraint belongs in the workflow. The distinction:

- **Workflow requirement** -- represents *processing progress*. Answers: "has
  the analyst or agent done the work expected at this phase?" Examples:
  assigning an owner, creating affects, filing trackers.
- **Model validation** -- represents *data sanity*. Answers: "is this data
  internally consistent?" Examples: CVSS score consistency, date format
  validity, CVE description length.

Model validations belong in `osidb/models/` validators and are enforced on
every save regardless of workflow state. Workflow requirements belong in YAML
and gate state progression.

### Planned Restorations (TODO restore)

The following requirements should be restored to PRE_SECONDARY_ASSESSMENT:

- `has affects` -- a flaw cannot progress past triage without at least one
  affect identifying which products are impacted
- `has impact` -- impact assessment is a core triage output

Further enrichment of requirements across all states is planned but requires
deeper analysis of the processing phases and team input.

## REJECTED Workflow

The REJECTED workflow handles flaws that have been rejected during triage. It
is driven by a **workflow label**: when a `FlawCollaborator` with
`label="rejected"` and `type="workflow"` exists on a flaw, `classify()` selects
the REJECTED workflow.

### Label-Driven Classification

Workflow labels drive classification through parameterized method checks.
The `Flaw.has_label(label)` method checks for the presence of a workflow label.
The REJECTED workflow YAML uses the readable parameterized syntax:

```yaml
name: REJECTED
priority: 1
conditions:
  - has label rejected
states:
  - name: DONE
    jira_state: Closed
    jira_resolution: Won't Do
    requirements: []
```

The check `has label rejected` is parsed (spaces converted to underscores) and
interpreted as a call to `has_label("rejected")`.

Because REJECTED has priority 1 (higher than DEFAULT's 0), it is evaluated
first. When a "rejected" workflow label exists, the flaw is classified into
REJECTED/DONE. When the label is removed, the condition fails and the flaw
falls back to DEFAULT, where it is classified normally based on its data.

**Parameterized Check Syntax:**

Workflow checks support parameterized methods with a human-readable syntax.
Spaces are converted to underscores during parsing, then the check is split on
the last underscore to extract the method name and parameter.

Examples:
- `has label approved` → `has_label("approved")`
- `has label escalated` → `has_label("escalated")`
- `has component kernel` → `has_component("kernel")`

Negative checks are also supported using the `not` prefix:
- `not has label rejected` → `not has_label("rejected")`
- `not has component systemd` → `not has_component("systemd")`

Any method accepting `self` + one parameter can be used this way.

### WORKFLOW Label Type

The `FlawLabel.FlawLabelType.WORKFLOW` type was introduced for labels that
drive workflow classification. Unlike context-based labels, WORKFLOW labels:

- Do not require pre-registration in the `FlawLabel` table
- Can be added in any workflow state (no PRE_SECONDARY_ASSESSMENT restriction)

This type is designed to be reusable for future workflow-driving labels beyond
rejection (e.g., approval labels).

### Fixed State Set

All workflows share a fixed set of states defined in `WorkflowState`. The
REJECTED workflow uses the DONE state (not a separate REJECTED state) because
DONE represents "fully processed" -- a rejected flaw has been fully processed
by the act of rejecting it. The Jira resolution distinguishes rejection
("Won't Do") from completion ("Done").

### ACL Handling

Rejected flaws with internal ACLs are **not** promoted to public even though
their workflow state is DONE. The `adjust_acls` method checks
`workflow_name != "REJECTED"` to prevent this.

## Jira Integration

The data flow between OSIDB and Jira is strictly one-directional for workflow classification:

**OSIDB to Jira:** When classification changes, it gets transitioned to the
Jira task using the forward mapping. The Jira state/resolution metadata in YAML workflow
definitions specifies the mapping.

**Jira to OSIDB:** Only task metadata updates from Jira. It does
not map Jira status/resolution back to workflow fields.

## API
The deprecated mutation endpoints (`promote`, `revert`, `reset`, `reject`,
`adjust`) remain authenticated for backwards compatibility but are no-ops.

### Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/workflows/api/v1/workflows` | GET | List all workflow definitions |
| `/workflows/api/v1/workflows/{id}` | GET | Get computed classification for a flaw |
| `/workflows/api/v1/workflows/{id}/adjust` | POST | **Deprecated** no-op, returns current classification |
| `/workflows/api/v1/graph/workflows` | GET | Visual (Mermaid) diagram of all workflows |
| `/workflows/api/v1/graph/workflows/{id}` | GET | Visual diagram with flaw classification highlighted |

Classification is automatic based on flaw data and cannot be manually changed.

### Graph Endpoints

The graph endpoints render an HTML page with Mermaid flowchart diagrams of
workflow states. The plain `/graph/workflows` shows all workflow definitions.
The `/graph/workflows/{id}` variant classifies a specific flaw and highlights
states with color: blue for the classified state, green for accepting, red for
non-accepting.

### Deprecated Mutation Endpoints

The mutation endpoints (`promote`, `revert`, `reset`, `reject`) live under
`/osidb/api/v1/flaws/{id}/` in the main OSIDB URL configuration, not the
workflows app. The `adjust` endpoint (`/workflows/api/v1/workflows/{id}/adjust`)
is in the workflows app. All are no-ops that return the current classification
with deprecation warnings and will be removed in a future version.

To change workflow state, update flaw data directly.
Classification updates automatically on every flaw save.
