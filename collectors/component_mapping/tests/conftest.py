import pytest


@pytest.fixture(autouse=True)
def enable_db_access_for_all_tests(db):
    pass


@pytest.fixture
def component_mapping_url():
    return "https://example.com/prodsec/source-component-mapping/-/jobs/artifacts/main/raw/component_mapping.json"
