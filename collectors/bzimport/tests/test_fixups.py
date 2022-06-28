import logging

import pytest

# TODO parsed_fixed_in was turned into FlawBugConvertor.package_versions
# TODO fixup_affect_ps_module was integrated in the AffectFixer
# TODO refactor after JobItem removal

# from collectors.bzimport.fixups import fixup_affect_ps_module, parse_fixed_in
# from osidb.tests.factories import AffectFactory

logger = logging.getLogger(__name__)
pytestmark = pytest.mark.unit


# class TestFixups(object):
#     def test_find_package_multi(self):
#         input = "django 3.2.5, django 3.1.13"
#         package = parse_fixed_in(input, None)
#         assert package["django"] == ["3.2.5", "3.1.13"]

#     def test_find_package_single(self):
#         input = "django 3.2.5"
#         package = parse_fixed_in(input, None)
#         assert package["django"] == ["3.2.5"]

#     def test_find_package_single_dash(self):
#         input = "django-3.2.5"
#         package = parse_fixed_in(input, None)
#         assert package["django"] == ["3.2.5"]

#     def test_find_package_multi_dash(self):
#         input = "python-pillow-2.8.0"
#         package = parse_fixed_in(input, None)
#         assert package["python-pillow"] == ["2.8.0"]

#     def test_find_package_no_value(self):
#         input = ""
#         job_item = JobItem()
#         package_versions = parse_fixed_in(input, job_item)
#         assert job_item.bz_data_score == 0
#         assert package_versions.items() is not None

#     def test_find_package_null_value(self):
#         input = None
#         job_item = JobItem()
#         package_versions = parse_fixed_in(input, job_item)
#         assert job_item.bz_data_score == 0
#         assert package_versions.items() is not None

#     def test_find_package_with_golang(self):
#         input_value = "github.com/gogo/protobuf 1.3.2"
#         package = parse_fixed_in(input_value, None)
#         assert package["github.com/gogo/protobuf"] == ["1.3.2"]

#     def test_parse_fixed_in_multi_package(self):
#         input_value = "a 1, b 1"
#         jobitem = JobItem()
#         result = parse_fixed_in(input_value, jobitem)
#         assert result["a"] == ["1"]
#         assert result["b"] == ["1"]

#     def test_parse_fixed_in_multi_package_dash(self):
#         input_value = "a-1, b 1"
#         jobitem = JobItem()
#         result = parse_fixed_in(input_value, jobitem)
#         assert result["a"] == ["1"]
#         assert result["b"] == ["1"]

#         input_value = "a-1, b-1"
#         jobitem = JobItem()
#         result = parse_fixed_in(input_value, jobitem)
#         assert result["a"] == ["1"]
#         assert result["b"] == ["1"]

#         input_value = "a 1, b-1"
#         jobitem = JobItem()
#         result = parse_fixed_in(input_value, jobitem)
#         assert result["a"] == ["1"]
#         assert result["b"] == ["1"]

# def test_affect_ps_module_fixup(
#     self, affect_incorrect_module, affect_correct_module
# ):

#     affect = AffectFactory()
#     assert affect_incorrect_module != affect_correct_module

#     # should fixup the affect with incorrect module to be like the one with
#     # the correct module
#     fixup_affect_ps_module(affect, affect_incorrect_module)
#     assert affect.ps_module == affect_correct_module

#     affect = AffectFactory(ps_module=affect_correct_module)
#     # should not change the affect with correct module at all
#     fixup_affect_ps_module(affect, affect_correct_module)
#     assert affect.ps_module == affect_correct_module
