import pytest


@pytest.fixture(autouse=True)
def enable_db_access_for_all_tests(db):
    pass


@pytest.fixture
def flaw_labels_url():
    return "https://example.com/prodsec/psirt/osim-flaw-labeling/-/raw/main/mapping/flaw_label_mapping.yaml"
