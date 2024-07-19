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

    For general reasoning about locking in OSIDB, see SelectForUpdateMixin.

    SelectForUpdateMixin is for a more limited usecase, much simpler and
    easier to understand, hence the split implementation and split explanation.

    For reasoning about using a consistent reusable approach outside of
    SelectForUpdateMixin and usage of this function, read on:

    Flaw, Affect and Tracker relationships are traversed and the whole graph
    is locked always in the order:
    1. all identified Flaws,
    2. all identified Affects
    3. all identified Trackers

    Even though locking all related/linked instances of all three models
    is not necessary in most situations if locking is used in all cases
    of writing data, it is useful because
    - locking blocks other threads that use locks too from reading,
      making concurrent tasks execute serially on related data,
      maintaining data consistency
    - locking blocks other threads writing even if they didn't lock
      (for example by mistake, which is highly probable to occur sometime
       during development), thus reducing potential impact of future bugs
    - in some cases, the some of the instances are not connected yet
      at the start of the processing, making locking only on e.g. Flaw
      insufficient
    - having a single piece of logic with consistent locking order
      is more maintainable and easier to reason about than theoretically
      more optimized approaches (and concurrency is difficult to reason
      about in OSIDB)

    A deadlock is possible if two threads use this function to first lock
    two different sets of models, then each wants to additionally lock
    some of models already locked by the other thread. Discovering as much
    of the related models before the first locking in the transaction helps
    avoid that. If it happens, Postgresql should detect it and abort the
    transaction.
    It shouldn't happen though because:
    - When a collector collects a time range, it locks incrementally
      (because it can't know all IDs in advance), but only a single instance
      of such a process should run at a time.
    - When a collector collects an object identified by an ID, it
      usually performs only one round of locking, or it does its best
      to make the first round of locking as complete as possible.

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
