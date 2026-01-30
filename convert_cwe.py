# with shell_plus Flaw will be available
from osidb.models.flaw.flaw import Flaw

full_data= {
    "7f8480f9-b584-476d-92cb-f132f5be8b22": "CWE-918",  # 1
    "edfb164a-306b-437b-9c5a-9950b2e73f52": "CWE-639",  # 2
    "4963d367-409d-4748-8edb-2426f7c1025f": "CWE-79",  # 3   
} # just an example, orignal has almost 7000 items


import uuid 
from django.db.models import Case, CharField, Value, When
from django.utils import timezone
CHUNK_SIZE = 500

def _chunks(items: list[tuple[str, str]], size: int) -> list[list[tuple[str, str]]]:
    return [items[i : i + size] for i in range(0, len(items), size)]

# Improved version of the script
def apply_cwe_updates() -> None:
    cwe_updates = full_data
    if not cwe_updates:
        return
    updates = sorted(cwe_updates.items(), key=lambda kv: kv[0])
    for chunk in _chunks(updates, CHUNK_SIZE):
        now = timezone.now().replace(microsecond=0)
        print(f'Updating {len(chunk)} flaws at {now}')
        uuids = [uuid.UUID(flaw_uuid) for flaw_uuid, _ in chunk]
        cwe_case = Case(
            *[
                When(uuid=uuid.UUID(flaw_uuid), then=Value(cwe_id))
                for flaw_uuid, cwe_id in chunk
            ],
            output_field=CharField(),
        )
        Flaw.objects.filter(uuid__in=uuids).update(
        cwe_id=cwe_case,updated_dt=now, local_updated_dt=now
        )

