# pylint: disable=E0402, R0902, R0903
"""" Implements PolicyRule child class for ZIA FileType rules"""

from typing import Self, Callable

from .policy_rule import PolicyRule


class FileTypeRule(PolicyRule):
    """
        PolicyRule entity corresponds to a ZIA FileType rule entry

        Some parameters might be missing from the data, so their existence
        has to be checked before using. Lists are defined inconsistently either
        as attribute lists of sub-json lists, thus different processing
        (see "name" attribute assignment)
    """

    name: str = ""
    description: str = ""
    labels: set[str] = ()
    order: int = 0
    rank: int = 0
    action: str = ""
    state: str = ""
    locations: set[str] = ()
    location_groups: set[str] = ()
    users: set[str] = ()
    user_groups: set[str] = ()
    user_devices: set[str] = ()
    user_device_groups: set[str] = ()
    device_trust_levels: set[str] = ()
    departments: set[str] = ()
    zpa_app_segments: set[str] = ()
    url_categories: set[str] = ()
    cloud_apps: set[str] = ()
    time_window: set[str] = ()
    protocols: set[str] = ()
    file_types: set[str] = ()
    min_size: int = 0
    max_size: int = 0
    capture_pcap: bool = False
    operation: str = ""
    active_content: bool = False
    unscannable: bool = False

    def __init__(self, js):
        """
            Initialize object from a dictionary. FileType API is not published, has to be
            reversed from ZSUI calls using any web browser (JS calls the APIs)

            :param json js: dictionary, built from ZSUI reverse engineering
        """
        self.name = js["name"]
        self.order = js["order"]
        self.rank = js["rank"]
        self.action = js["filteringAction"]
        self.state = js["state"]
        self.description = js.get("description", "")
        self.labels = set(x["name"] for x in js.get("labels", []))
        self.locations = set(x["name"] for x in js.get("locations", []))
        self.location_groups = set(x["name"] for x in js.get("locationGroups", []))
        self.users = set(x["name"] for x in js.get("users", []))
        self.user_groups = set(x["name"] for x in js.get("groups", []))
        self.user_devices = set(x["name"] for x in js.get("devices", []))
        self.user_device_groups = set(x["name"] for x in js.get("deviceGroups", []))
        self.device_trust_levels = set(js.get("deviceTrustLevels", []))
        self.departments = set(x["name"] for x in js.get("departments", []))
        self.zpa_app_segments = set(x["name"] for x in js.get("zpaAppSegments", []))
        self.url_categories = set(js.get("urlCategories", []))
        self.cloud_apps = set(js.get("cloudApplications", []))
        self.time_window = set(x["name"] for x in js.get("timeWindows", []))
        self.protocols = set(js.get("protocols", []))
        self.file_types = set(js.get("fileTypes", []))
        self.capture_pcap = js.get("capturePCAP", False)
        self.operation = js.get("operation", "")
        self.active_content = js.get("activeContent", False)
        self.unscannable = js.get("unscannable", False)

    def distance_from(self, file_rule: Self) -> float:
        """
            Define distance to another rule as the number of criteria that do not match.

            :param FileTypeRule file_rule: Vector to compute distance to

            :return Real value of distance to vector
        """
        distance = 0

        distance += not self.action == file_rule.action
        distance += not self.state == file_rule.state
        distance += not self.locations == file_rule.locations
        distance += not self.location_groups == file_rule.location_groups
        distance += not self.users == file_rule.users
        distance += not self.user_groups == file_rule.user_groups
        distance += not self.user_devices == file_rule.user_devices
        distance += not self.user_device_groups == file_rule.user_device_groups
        distance += not self.device_trust_levels == file_rule.device_trust_levels
        distance += not self.departments == file_rule.departments
        distance += not self.zpa_app_segments == file_rule.zpa_app_segments
        distance += not self.url_categories == file_rule.url_categories
        distance += not self.cloud_apps == file_rule.cloud_apps
        distance += not self.time_window == file_rule.time_window
        distance += not self.protocols == file_rule.protocols
        distance += not self.file_types == file_rule.file_types
        distance += not self.min_size == file_rule.min_size
        distance += not self.max_size == file_rule.max_size
        distance += not self.capture_pcap == file_rule.capture_pcap
        distance += not self.operation == file_rule.operation
        distance += not self.active_content == file_rule.active_content
        distance += not self.unscannable == file_rule.unscannable

        return distance

    def _key(self) -> tuple:
        """
            Implement base abstract method. Order value is unique per rule – can be used as key.

            :return tuple[int]
        """
        return (self.order,)


class FileTypeRuleWithSubsets(FileTypeRule):
    """
        FileTypeRule entity that checks whether rule A is a subset of rule B
        and vice versa.
    """

    def distance_from(self, file_rule: Self) -> float:
        """
            Define distance to another rule as a number of match criteria that do not
            match. If criterion of rule A is a subset of criterion from rule B, such
            a criterion does not contribute to the distance.

            Note: distance(A,B) != distance(B,A) in general case. However, triangle
            inequality is still satisfied (distance(A,C) < distance(A,B) + distance(B,C)),
            because the whole set is searched through.

            :param FileTypeRule file_rule: Vector to compute distance to

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
            obj1 = self if i == 0 else file_rule
            obj2 = file_rule if i == 0 else self

            distance[i] += not obj1.action == obj2.action
            distance[i] += not obj1.state == obj2.state
            distance[i] += obj1.min_size != obj2.min_size
            distance[i] += obj1.max_size != obj2.max_size
            distance[i] += not obj1.capture_pcap == obj2.capture_pcap
            distance[i] += not obj1.operation == obj2.operation
            distance[i] += not obj1.active_content == obj2.active_content
            distance[i] += not obj1.unscannable == obj2.unscannable
            distance[i] += not is_subset(obj1.locations, obj2.locations)
            distance[i] += not is_subset(obj1.location_groups, obj2.location_groups)
            distance[i] += not is_subset(obj1.users, obj2.users)
            distance[i] += not is_subset(obj1.user_groups, obj2.user_groups)
            distance[i] += not is_subset(obj1.user_devices, obj2.user_devices)
            distance[i] += not is_subset(obj1.user_device_groups, obj2.user_device_groups)
            distance[i] += not is_subset(obj1.device_trust_levels, obj2.device_trust_levels)
            distance[i] += not is_subset(obj1.departments, obj2.departments)
            distance[i] += not is_subset(obj1.zpa_app_segments, obj2.zpa_app_segments)
            distance[i] += not is_subset(obj1.url_categories, obj2.url_categories)
            distance[i] += not is_subset(obj1.cloud_apps, obj2.cloud_apps)
            distance[i] += not is_subset(obj1.time_window, obj2.time_window)
            distance[i] += not is_subset(obj1.protocols, obj2.protocols)
            distance[i] += not is_subset(obj1.file_types, obj2.file_types)

        return min(distance)
