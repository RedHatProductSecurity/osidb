# Generated manually for incident state migration

from django.db import migrations, models


def migrate_incident_states(apps, schema_editor):
    """
    Migrate old major incident states to new ones.
    
    Old states -> New states mapping:
    - REQUESTED -> MAJOR_INCIDENT_REQUESTED
    - REJECTED -> MAJOR_INCIDENT_REJECTED  
    - APPROVED -> MAJOR_INCIDENT_APPROVED
    - CISA_APPROVED -> EXPLOITS_KEV_APPROVED
    - MINOR -> MINOR_INCIDENT_APPROVED
    - ZERO_DAY -> ""
    - INVALID -> ""
    - "" -> "" (no change)
    """
    Flaw = apps.get_model('osidb', 'Flaw')
    FlawAudit = apps.get_model('osidb', 'FlawAudit')
    
    state_mapping = {
        'REQUESTED': 'MAJOR_INCIDENT_REQUESTED',
        'REJECTED': 'MAJOR_INCIDENT_REJECTED',
        'APPROVED': 'MAJOR_INCIDENT_APPROVED',
        'CISA_APPROVED': 'EXPLOITS_KEV_APPROVED',
        'MINOR': 'MINOR_INCIDENT_APPROVED',
        'ZERO_DAY': '',
        'INVALID': '',
    }
    
    for old_state, new_state in state_mapping.items():
            Flaw.objects.filter(
                major_incident_state=old_state
            ).update(major_incident_state=new_state)

            FlawAudit.objects.filter(
                major_incident_state=old_state
            ).update(major_incident_state=new_state)

def reverse_migrate_incident_states(apps, schema_editor):
    """
    Reverse migration. Converts new states back to old ones.
    Note: This is a lossy conversion.
    """
    Flaw = apps.get_model('osidb', 'Flaw')
    FlawAudit = apps.get_model('osidb', 'FlawAudit')
    
    # Reverse mapping (note: this is lossy)
    reverse_mapping = {
        'MAJOR_INCIDENT_REQUESTED': 'REQUESTED',
        'MAJOR_INCIDENT_REJECTED': 'REJECTED',
        'MAJOR_INCIDENT_APPROVED': 'APPROVED',
        'EXPLOITS_KEV_REQUESTED': 'REQUESTED', 
        'EXPLOITS_KEV_REJECTED': 'REJECTED', 
        'EXPLOITS_KEV_APPROVED': 'CISA_APPROVED',
        'MINOR_INCIDENT_APPROVED': 'MINOR',
        'MINOR_INCIDENT_REQUESTED': '',  
        'MINOR_INCIDENT_REJECTED': '',   
    }
    
    for new_state, old_state in reverse_mapping.items():
        Flaw.objects.filter(
            major_incident_state=new_state
        ).update(major_incident_state=old_state)
            
        FlawAudit.objects.filter(
            major_incident_state=new_state
        ).update(major_incident_state=old_state)



class Migration(migrations.Migration):

    dependencies = [
        ('osidb', '0208_fix_flaw_dependent_object_acls'),
    ]

    operations = [
        migrations.AlterField(
            model_name='flaw',
            name='major_incident_state',
            field=models.CharField(blank=True, choices=[('', 'Novalue'), ('MAJOR_INCIDENT_REQUESTED', 'Major Incident Requested'), ('MAJOR_INCIDENT_REJECTED', 'Major Incident Rejected'), ('MAJOR_INCIDENT_APPROVED', 'Major Incident Approved'), ('EXPLOITS_KEV_REQUESTED', 'Exploits Kev Requested'), ('EXPLOITS_KEV_REJECTED', 'Exploits Kev Rejected'), ('EXPLOITS_KEV_APPROVED', 'Exploits Kev Approved'), ('MINOR_INCIDENT_REQUESTED', 'Minor Incident Requested'), ('MINOR_INCIDENT_REJECTED', 'Minor Incident Rejected'), ('MINOR_INCIDENT_APPROVED', 'Minor Incident Approved')], max_length=24),
        ),
        migrations.AlterField(
            model_name='flawaudit',
            name='major_incident_state',
            field=models.CharField(blank=True, choices=[('', 'Novalue'), ('MAJOR_INCIDENT_REQUESTED', 'Major Incident Requested'), ('MAJOR_INCIDENT_REJECTED', 'Major Incident Rejected'), ('MAJOR_INCIDENT_APPROVED', 'Major Incident Approved'), ('EXPLOITS_KEV_REQUESTED', 'Exploits Kev Requested'), ('EXPLOITS_KEV_REJECTED', 'Exploits Kev Rejected'), ('EXPLOITS_KEV_APPROVED', 'Exploits Kev Approved'), ('MINOR_INCIDENT_REQUESTED', 'Minor Incident Requested'), ('MINOR_INCIDENT_REJECTED', 'Minor Incident Rejected'), ('MINOR_INCIDENT_APPROVED', 'Minor Incident Approved')], max_length=24),
        ),
        migrations.RunPython(
            code = migrate_incident_states,
            reverse_code = reverse_migrate_incident_states,
            atomic = True
        ),
    ]
