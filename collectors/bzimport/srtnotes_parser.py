"""
This code is just a copy-paste from the flaw.py module from the prodsec python library
becuase in order to be able to opensource OSIDB we need to get rid of the prodsec
library which is not public.
"""


import json
import re
import warnings
from datetime import datetime


class WhiteboardWarning(UserWarning):
    """An abstract warning that all whiteboard warnings inherit from. Useful for filtering."""

    pass


class WhiteboardUnknownAffectsValue(WhiteboardWarning):
    pass


class WhiteboardUnexpectedAttribute(WhiteboardWarning):
    pass


class WhiteboardMalformedDatetime(WhiteboardWarning):
    pass


class WhiteboardUnknownAffectsAttribute(WhiteboardWarning):
    pass


class WhiteboardMalformedPSComponent(WhiteboardWarning):
    pass


class WhiteboardMalformedCVSS(WhiteboardWarning):
    pass


# these cannot be in attribute names or values
WHITEBOARD_SEPARATORS = [",", "="]

FLAW_ATTRIBUTES = [
    "impact",
    "public",
    "reported",
    "source",
    "cvss2",
    "cvss3",
    "cwe",
    "mitigate",
    "classification",
    "jira_trackers",
]

DATETIME_FIELDS = ["public", "reported"]
DATE_FMT = "%Y%m%d"
DATETIME_FMT = "%Y%m%d:%H%M"
AFFECTS_STATES = ["new", "affected", "notaffected", "defer", "wontfix"]

PRODUCT_ATTRIBUTES = {
    "impact": r"^impact=",
    "cvss2": r"^(cvss2|cvssv2)=",
    "cvss3": r"^cvss3=",
}


def _parse_date(attribute, date):
    try:
        if len(date) == 20:  # '2019-04-17T19:31:14Z'
            return datetime.strptime(date, "%Y-%m-%dT%H:%M:%SZ"), None
        elif len(date) == 10:  # '2019-04-17'
            return datetime.strptime(date, "%Y-%m-%d"), None
        else:
            raise ValueError("Unknown format")
    except ValueError as e:
        return None, WhiteboardMalformedDatetime(
            '{2}: Malformed {0} datetime value in whiteboard: "{1}"'.format(
                attribute, date, str(e)
            )
        )


def _parse_date_fields(srtnotes, datetime_fields):
    warns = []

    for field in datetime_fields:
        if srtnotes[field]:
            srtnotes[field], warning = _parse_date(field, srtnotes[field])
            if warning:
                warns.append(warning)

    return srtnotes, warns


def _parse_affects(srtnotes):
    warns = []

    for affect in srtnotes["affects"]:
        # Parse module_name:module_stream/component into its separate parts for convenience
        # if some tool wants a particular piece of it.
        # See _parse_product_affected() for a similar regex.
        re_pattern = r"""
        (?:(?P<module_name>[^:/]*):(?P<module_stream>[^/]*)/)?  # optional module_name:module_stream/
        (?P<component>[^:/=]*)                                  # component
        """
        match = _fullmatch(re_pattern, affect["ps_component"], re.VERBOSE)

        # This regex /should/ always match if it's following the schema. If not raise a warning.
        if not match:
            warns.append(
                WhiteboardMalformedPSComponent(
                    'Malformed PSComponent: "{}"'.format(affect["ps_component"])
                )
            )
        else:
            affect.update(match.groupdict())

    return srtnotes, warns


def parse_cf_srtnotes(cf_srtnotes, return_warnings=False, revision=1):
    """
    Parses the contents of cf_srtnotes and returns a dictionary representation. In addition to simple json parsing:
    1) convert date / datetime fields to dates / datetimes
    2) split out some extra information from ps_component entries for convenience.
      * Adds 'module_name', 'module_stream', and 'component' that are parsed out of ps_component
    3) adds 'cvss[2,3]_score', 'cvss[2,3]_vector' attributes, which are split out from the whole cvss attribute

    The 'return_warnings' arg allows you to specify warning behavior. If False (default)
    warnings will be "raised" with warnings.warn. If True then instead of raising them
    a list of warnings will be returned along with the parsed cf_srtnotes.

    Note that although this function does not check for schema validity (it would make more sense to do that at
    write time) we generally expect things to follow the schema definition.
    See SFM2 git repo /sfm2/schemas/flaw_cf_srtnotes.json

    If return_warnings == False (default):
      Returns: parsed_cf_srtnotes_dict
    If return_warnings == True or revision >= 2:
      Returns: (parsed_cf_srtnotes_dict, array_of_warnings)

    Warnings can include WhiteboardMalformedDatetime, WhiteboardMalformedPSComponent, and WhiteboardMalformedCVSS.

    Revisions:

        1 -- initial
        2 -- return warnings as second parameter
        3 -- return mitigate as array

    """
    srtnotes = {
        "checklists": [],
        "impact": None,
        "public": None,
        "reported": None,
        "source": None,
        "cvss2": None,
        "cvss3": None,
        "cvss3_comment": None,
        "cwe": None,
        "mitigate": None,
        "classification": None,
        "affects": [],
        "references": [],
        "jira_trackers": [],
        "statement": None,
        "mitigation": None,
        "acknowledgments": [],
        "acks_not_needed": None,
    }
    srtnotes.update(json.loads(cf_srtnotes))

    # convert date / datetime fields to dates / datetimes
    srtnotes, warns = _parse_date_fields(srtnotes, DATETIME_FIELDS)

    if srtnotes["mitigate"]:
        if revision < 3 and isinstance(srtnotes["mitigate"], (list, tuple)):
            # transform array to a string, as a string is expected for sfm2 <=2.6.0,
            # https://bugzilla.redhat.com/show_bug.cgi?id=1717440
            srtnotes["mitigate"] = "|".join(srtnotes["mitigate"])
        if revision >= 3 and isinstance(srtnotes["mitigate"], str):
            # transform string into array, as the array is expected for the JSON schema
            srtnotes["mitigate"] = srtnotes["mitigate"].split("|")

    for field in ("cvss2", "cvss3"):
        if srtnotes[field]:
            try:
                score, vector = srtnotes[field].split("/", 1)
                srtnotes[field + "_score"] = float(score)
                srtnotes[field + "_vector"] = vector
            except (TypeError, ValueError) as e:
                warns.append(
                    WhiteboardMalformedCVSS(
                        'Malformed CVSS entry {}: "{}", {}'.format(
                            field, srtnotes[field], str(e)
                        )
                    )
                )

        if not field + "_score" in srtnotes:
            srtnotes[field + "_score"] = srtnotes[field + "_vector"] = None

    srtnotes, _warns = _parse_affects(srtnotes)
    warns += _warns

    if return_warnings or revision >= 2:
        return srtnotes, warns
    else:
        for warning in warns:
            warnings.warn(warning)
        return srtnotes


def parse_whiteboard(whiteboard):
    """
    Parses the whiteboard and returns a dictionary.
    See FLAW_ATTRIBUTES for a list of keys that might exist in the dict.

    Can also cause warnings to be 'thrown' if if encouters bad data, so you can catch them and
    do something smarter if you want.
    """
    wb = {"affects": []}

    for wb_attr in whiteboard.split(","):

        if not wb_attr:
            continue

        # try to parse as product/component=value
        new_affect = _parse_product_affected(wb_attr)
        if new_affect:
            wb["affects"].append(new_affect)

        else:
            attr_name, attr_value = _parse_attribute(wb_attr)
            if attr_name and attr_value:
                wb[attr_name] = attr_value

    return wb


def _parse_attribute(raw_attribute):
    # Take whiteboard string containing attribute and parse it into Flaw
    # acceptable attribute.
    #
    # Returns tuple (attr_name, attr_value), where attr_name is
    # one of attributes of Flaw canonical model.

    attr_name, _, attr_value = raw_attribute.partition("=")

    # is such attribute expected in the whiteboard at all?
    if not attr_name or attr_name not in FLAW_ATTRIBUTES:
        warnings.warn(
            'Unexpected attribute in flaw whiteboard: "{0}"'.format(attr_name),
            WhiteboardUnexpectedAttribute,
        )
        return None, None

    # in the past we put "public=no" in the whiteboard - that should not
    # throw any warning. Corner case.
    if attr_name == "public" and attr_value == "no":
        return attr_name, None

    if attr_name in DATETIME_FIELDS:
        try:
            attr_value = datetime.strptime(attr_value, DATE_FMT)
        except ValueError:
            # Try datetime format parsing
            try:
                attr_value = datetime.strptime(attr_value, DATETIME_FMT)
            except ValueError:
                warnings.warn(
                    'Malformed {0} datetime value in flaw whiteboard: "{1}"'.format(
                        attr_name, attr_value
                    ),
                    WhiteboardMalformedDatetime,
                )
                attr_value = None

    return attr_name, attr_value


def _parse_affects_attributes(string):
    parsed = {}

    if not string:
        return parsed

    # splits attributes by / only when followed by `attrname=`
    elements = re.split(r"/(?=[^/]+=)", string)

    for raw_elem in elements:
        for attr_name in PRODUCT_ATTRIBUTES:
            if re.match(PRODUCT_ATTRIBUTES[attr_name], raw_elem):
                parsed[attr_name] = re.sub(PRODUCT_ATTRIBUTES[attr_name], "", raw_elem)
                break
        else:
            if raw_elem:
                warnings.warn(
                    'Unknown attribute in affects: "{0}"'.format(raw_elem),
                    WhiteboardUnknownAffectsAttribute,
                )

    return parsed


def _fullmatch(regex, string, flags=0):
    # Emulate python-3.4 re.fullmatch().
    return re.match("(?:" + regex + r")\Z", string, flags=flags)


def _parse_product_affected(string):
    # Parse ps_module/module_name:module_stream/ps_component=value/other_attributes.
    # I've tried to make this as readable as possible. There are two patterns that we use
    # repeatedly here:
    # 1) A named capturing group that consumes everything until it hits the next separating char:
    #    (?P<name>[^separating_characters]*)
    # 2) An unnamed non-capturing optional group that encapsulates a pattern that might or might
    #    not exist: (?:body)?
    re_pattern = r"""
    (?P<ps_module>[^/]*)                                    # ps_module
    (?:/(?P<module_name>[^:/]*):(?P<module_stream>[^/]*))?  # optional /module_name:module_stream
    /(?P<ps_component>[^=]*)=(?P<value>[^/]*)               # /ps_component=value
    (?:/(?P<other_attributes>.*))?                          # optional /other_attributes
    """
    match = _fullmatch(re_pattern, string, re.VERBOSE)

    # return None if this does not look like ps_module/ps_component=value
    if not match:
        return None

    affected = match.groupdict()

    if affected["value"] not in AFFECTS_STATES:
        warnings.warn(
            'Invalid affectedness value in "{ps_module}/{ps_component}={value}"'.format(
                **affected
            ),
            WhiteboardUnknownAffectsValue,
        )

    if affected["other_attributes"]:
        attributes = _parse_affects_attributes(affected["other_attributes"])
        del affected["other_attributes"]
        affected.update(**attributes)

    return affected
