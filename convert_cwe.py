# with shell_plus Flaw will be available
from osidb.models.flaw.flaw import Flaw

full_data= {
    "7f8480f9-b584-476d-92cb-f132f5be8b22": "CWE-918",  # 1
    "edfb164a-306b-437b-9c5a-9950b2e73f52": "CWE-639",  # 2
    "4963d367-409d-4748-8edb-2426f7c1025f": "CWE-79",  # 3   
} # just an example, orignal has almost 7000 items


# I know this is not the most efficient way to do this
# but I was asked to do this by Juan Perez de Algaba in the vex meeting
# acording to them there is no problem if it takes longer because they prefer to make sure it triggers
# the TrackingMixin
def set_cwe_id(from_item=0, to_item=10):
  for i, (k,v) in enumerate(full_data.items()):
    if i >= to_item:
      break
    if i < from_item:
      continue
    f=Flaw.objects.get(pk=k)
    f.cwe_id=v
    f.save()
    print(f'{i}/{len(full_data)}: {k}: {v}')