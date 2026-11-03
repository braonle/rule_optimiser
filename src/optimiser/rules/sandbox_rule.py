# pylint: disable=E0402, R0902, R0903
"""" Implements PolicyRule child class for ZIA Sandbox rules"""

from typing import Self, Callable

from .policy_rule import PolicyRule


class SandboxRule(PolicyRule):
    """
        PolicyRule entity corresponds to a ZIA Sandbox rule entry

        Some parameters might be missing from the data, so their existence
        has to be checked before using. Lists are defined inconsistently either
        as attribute lists of sub-json lists, thus different processing
        (see "name" attribute assignment)
    """

    name: str = ""
    description: str = ""
    labels: set[str] = ()
    state: str = ""
    order: int = 0
    rank: int = 0
    file_types: set[str] = ()
    url_categories: set[str] = ()
    users: set[str] = ()
    user_groups: set[str] = ()
    departments: set[str] = ()
    locations: set[str] = ()
    location_groups: set[str] = ()
    zpa_app_segments: set[str] = ()
    protocols: set[str] = ()
    sandbox_categories: set[str] = ()
    subsequent_action: str = ""
    first_action: str = ""
    ml_action_enabled: bool = False
    time_window: set[str] = ()
    user_devices: set[str] = ()
    user_device_groups: set[str] = ()

    def __init__(self, js):
        """
            Initialize object from a dictionary.

            :param json js: dictionary
        """
        self.name = js["name"]
        self.order = js["order"]
        self.rank = js["rank"]
        self.state = js["state"]
        self.description = js.get("description", "")
        self.labels = set(x["name"] for x in js.get("labels", []))
        self.locations = set(x["name"] for x in js.get("locations", []))
        self.location_groups = set(x["name"] for x in js.get("locationGroups", []))
        self.users = set(x["name"] for x in js.get("users", []))
        self.user_groups = set(x["name"] for x in js.get("groups", []))
        self.user_devices = set(x["name"] for x in js.get("devices", []))
        self.user_device_groups = set(x["name"] for x in js.get("deviceGroups", []))
        self.departments = set(x["name"] for x in js.get("departments", []))
        self.zpa_app_segments = set(x["name"] for x in js.get("zpaAppSegments", []))
        self.url_categories = set(js.get("urlCategories", []))
        self.time_window = set(x["name"] for x in js.get("timeWindows", []))
        self.protocols = set(js.get("protocols", []))
        self.file_types = set(js.get("fileTypes", []))
        self.sandbox_categories = set(js.get("baPolicyCategories", []))
        self.first_action = js["firstTimeOperation"]
        self.subsequent_action = js["baRuleAction"]
        self.ml_action_enabled = js["mlActionEnabled"]

    def distance_from(self, sb_rule: Self) -> float:
        """
            Define distance to another rule as the number of criteria that do not match.

            :param SandboxRule sb_rule: Vector to compute distance to

            :return Real value of distance to vector
        """
        distance = 0

        distance += not self.state == sb_rule.state
        distance += not self.locations == sb_rule.locations
        distance += not self.location_groups == sb_rule.location_groups
        distance += not self.users == sb_rule.users
        distance += not self.user_groups == sb_rule.user_groups
        distance += not self.user_devices == sb_rule.user_devices
        distance += not self.user_device_groups == sb_rule.user_device_groups
        distance += not self.departments == sb_rule.departments
        distance += not self.zpa_app_segments == sb_rule.zpa_app_segments
        distance += not self.url_categories == sb_rule.url_categories
        distance += not self.time_window == sb_rule.time_window
        distance += not self.protocols == sb_rule.protocols
        distance += not self.file_types == sb_rule.file_types
        distance += not self.sandbox_categories == sb_rule.sandbox_categories
        distance += not self.first_action == sb_rule.first_action
        distance += not self.subsequent_action == sb_rule.subsequent_action
        distance += not self.ml_action_enabled == sb_rule.ml_action_enabled

        return distance

    def _key(self) -> tuple:
        """
            Implement base abstract method. Order value is unique per rule – can be used as key.

            :return tuple[int]
        """
        return (self.order,)


class SandboxRuleWithSubsets(SandboxRule):
    """
        SandboxRule entity that checks whether rule A is a subset of rule B
        and vice versa.
    """

    def distance_from(self, sb_rule: Self) -> float:
        """
            Define distance to another rule as a number of match criteria that do not
            match. If criterion of rule A is a subset of criterion from rule B, such
            a criterion does not contribute to the distance.

            Note: distance(A,B) != distance(B,A) in general case. However, triangle
            inequality is still satisfied (distance(A,C) < distance(A,B) + distance(B,C)),
            because the whole set is searched through.

            :param SandboxRule sb_rule: Vector to compute distance to

            :return Real value of distance to vector
        """
        # st = () and superset = () -> is subset
        # st = (1,) and superset = () -> is subset
        # st = () and superset = (1,) -> not a subset
        # st = (1,2) and superset = (1,2,3) -> is a subset
        #
        # From the above 2 exceptions must be handled before comparing 2 tuples elementwise:
        # 1. if superset is empty, then it's always a superset
        # 2. if superset is not empty, but st is empty, then superset is not actually a superset
        is_subset: Callable[[set, set], bool] = lambda st, superset: (
                len(superset) == 0 or len(st) != 0 and st.issubset(superset))

        distance = [0, 0]

        for i in range(0,2):
            obj1 = self if i == 0 else sb_rule
            obj2 = sb_rule if i == 0 else self

            distance[i] += not obj1.state == obj2.state
            distance[i] += not is_subset(obj1.locations, obj2.locations)
            distance[i] += not is_subset(obj1.location_groups, obj2.location_groups)
            distance[i] += not is_subset(obj1.users, obj2.users)
            distance[i] += not is_subset(obj1.user_groups, obj2.user_groups)
            distance[i] += not is_subset(obj1.user_devices, obj2.user_devices)
            distance[i] += not is_subset(obj1.user_device_groups, obj2.user_device_groups)
            distance[i] += not is_subset(obj1.departments, obj2.departments)
            distance[i] += not is_subset(obj1.zpa_app_segments, obj2.zpa_app_segments)
            distance[i] += not is_subset(obj1.url_categories, obj2.url_categories)
            distance[i] += not is_subset(obj1.time_window, obj2.time_window)
            distance[i] += not is_subset(obj1.protocols, obj2.protocols)
            distance[i] += not is_subset(obj1.file_types, obj2.file_types)

            distance[i] += not is_subset(obj1.sandbox_categories, obj2.sandbox_categories)
            distance[i] += not obj1.first_action == obj2.first_action
            distance[i] += not obj1.subsequent_action == obj2.subsequent_action
            distance[i] += not obj1.ml_action_enabled == obj2.ml_action_enabled

        return min(distance)
