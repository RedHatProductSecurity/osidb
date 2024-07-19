LOCKED_FLAW_UUIDS = "locked_flaw_uuids"
LOCKED_AFFECT_UUIDS = "locked_affect_uuids"
LOCKED_TRACKER_UUIDS = "locked_tracker_uuids"


def apply_lock_state_template():
    """
    Shared state to be used by apply_lock within a transaction.
    """
    return {
        LOCKED_FLAW_UUIDS: set(),
        LOCKED_AFFECT_UUIDS: set(),
        LOCKED_TRACKER_UUIDS: set(),
    }


def apply_lock(
    state, new_flaw_uuids=None, new_affect_uuids=None, new_tracker_uuids=None
):
    """
    Locks Flaw, Affect, Tracker models based on the provided UUIDs.
    Flaw, Affect and Tracker relationships are traversed and the whole graph
    is locked always in the order:
    1. all identified Flaws,
    2. all identified Affects
    3. all identified Trackers
    A deadlock is possible if two threads use this function to first lock
    two different sets of models, then each wants to additionally lock
    some of models already locked by the other thread. Discovering as much
    of the related models before the first locking in the transaction helps
    avoid that. If it happens, Postgresql should detect it and abort the
    transaction.
    It shouldn't happen though because:
    - When Jira*Collector collects a time range, it locks incrementally
      (because it can't know all IDs in advance), but only a single instance
      of such a process should run at a time.
    - When Jira*Collector collects an object identified by an ID, it most
      probably performs only one round of locking.
    For reasoning about locking, see SelectForUpdateMixin.
    Modifies the "state" argument.
    The new*uuids arguments must be iterable.
    Must be run inside a transaction.
    """

    # Prevent circular imports
    from osidb.models import Affect, Flaw, Tracker

    new_flaw_uuids = set(new_flaw_uuids) if new_flaw_uuids else set()
    new_affect_uuids = set(new_affect_uuids) if new_affect_uuids else set()
    new_tracker_uuids = set(new_tracker_uuids) if new_tracker_uuids else set()

    all_flaw_uuids = state[LOCKED_FLAW_UUIDS] | set(new_flaw_uuids)
    all_affect_uuids = state[LOCKED_AFFECT_UUIDS] | set(new_affect_uuids)
    all_tracker_uuids = state[LOCKED_TRACKER_UUIDS] | set(new_tracker_uuids)

    for i in range(2):
        # Twice to discover the whole graph. Any of the new_*_uuids sets
        # can be empty/nonempty, requiring different directions in
        # the graph traversal. A single direction iterated twice is simpler
        # to understand.

        # discover flaw uuids from affect
        all_flaw_uuids.update(
            set(
                Affect.objects.filter(uuid__in=all_affect_uuids).values_list(
                    "flaw__uuid", flat=True
                )
            )
        )

        # discover affect uuids from flaw
        all_affect_uuids.update(
            set(
                Flaw.objects.filter(uuid__in=all_flaw_uuids).values_list(
                    "affects__uuid", flat=True
                )
            )
        )

        # discover affect uuids from tracker
        all_affect_uuids.update(
            set(
                Tracker.objects.filter(uuid__in=all_tracker_uuids).values_list(
                    "affects__uuid", flat=True
                )
            )
        )

        # discover tracker uuids from affect
        all_tracker_uuids.update(
            set(
                Tracker.objects.filter(affects__uuid__in=all_affect_uuids).values_list(
                    "uuid", flat=True
                )
            )
        )

    nonlocked_flaw_uuids = all_flaw_uuids - state[LOCKED_FLAW_UUIDS]
    nonlocked_affect_uuids = all_affect_uuids - state[LOCKED_AFFECT_UUIDS]
    nonlocked_tracker_uuids = all_tracker_uuids - state[LOCKED_TRACKER_UUIDS]

    Flaw.objects.filter(uuid__in=nonlocked_flaw_uuids).select_for_update()
    state[LOCKED_FLAW_UUIDS].update(nonlocked_flaw_uuids)

    Affect.objects.filter(uuid__in=nonlocked_affect_uuids).select_for_update()
    state[LOCKED_AFFECT_UUIDS].update(nonlocked_affect_uuids)

    Tracker.objects.filter(uuid__in=nonlocked_tracker_uuids).select_for_update()
    state[LOCKED_TRACKER_UUIDS].update(nonlocked_tracker_uuids)
