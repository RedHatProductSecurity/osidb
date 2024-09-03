import pytest


@pytest.fixture(autouse=True)
def enable_db_access_for_all_tests(db):
    pass


@pytest.fixture
def product_definition_url():
    return "https://example.com/prodsec/product-definitions/-/jobs/artifacts/master/raw/products.json"
