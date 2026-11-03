# pylint: disable=E0402, R0902, R0903
"""" Implements PolicyRule child class for ZIA URL filtering rules"""

from typing import Self, Callable

from .policy_rule import PolicyRule


class URLRule(PolicyRule):
    """
        PolicyRule entity corresponds to a ZIA URL filtering rule entry

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
    src_ip_groups: set[str] = ()
    src_ipv6_groups: set[str] = ()
    locations: set[str] = ()
    location_groups: set[str] = ()
    users: set[str] = ()
    user_groups: set[str] = ()
    user_devices: set[str] = ()
    user_device_groups: set[str] = ()
    device_trust_levels: set[str] = ()
    departments: set[str] = ()
    url_categories: set[str] = ()
    user_agents: set[str] = ()
    protocols: set[str] = ()
    request_methods: set[str] = ()
    time_window: set[str] = ()
    workload_group: set[str] = ()
    notification_url: str = ""
    override_users: set[str] = ()
    override_groups: set[str] = ()
    override_block: bool = False
    time_quota: int = 0
    size_quota: int = 0
    validity_start_time: int = 0
    validity_end_time: int = 0
    validity_zone_id: str = ""
    last_modified_time: int = 0
    last_modified_by: str = ""
    enforce_time_validity: bool = False
    cbi_profile: str = ""
    user_risk_score: set[str] = ()
    source_countries: set[str] = ()

    def __init__(self, js):
        """
            Initialize object from a dictionary. JSON for ZIA URL Filtering rule:
            https://help.zscaler.com/zia/url-filtering-policies#/urlFilteringRules-get

            Note that some of the fields are missing from the documentation and have been
            reverse engineered from ZSUI.

            :param json js: dictionary, built from ZIA API response without modification
        """
        self.name = js["name"]
        self.order = js["order"]
        self.rank = js["rank"]
        self.action = js["action"]
        self.state = js["state"]
        self.description = js.get("description", "")
        self.labels = set(x["name"] for x in js.get("labels", []))
        self.src_ip_groups = set(x["name"] for x in js.get("sourceIpGroups", []))
        self.src_ipv6_groups = set(x["name"] for x in js.get("sourceIpv6Groups", []))
        self.locations = set(x["name"] for x in js.get("locations", []))
        self.location_groups = set(x["name"] for x in js.get("locationGroups", []))
        self.users = set(x["name"] for x in js.get("users", []))
        self.user_groups = set(x["name"] for x in js.get("groups", []))
        self.user_devices = set(x["name"] for x in js.get("devices", []))
        self.user_device_groups = set(x["name"] for x in js.get("deviceGroups", []))
        self.device_trust_levels = set(js.get("deviceTrustLevels", []))
        self.departments = set(x["name"] for x in js.get("departments", []))
        self.url_categories = set(js.get("urlCategories", []))
        self.user_agents = set(js.get("userAgentTypes", []))
        self.protocols = set(js.get("protocols", []))
        self.request_methods = set(js.get("requestMethods", []))
        self.time_window = set(x["name"] for x in js.get("timeWindows", []))
        self.workload_group = set(x["name"] for x in js.get("workloadGroups", []))
        self.notification_url = js.get("endUserNotificationUrl", "")
        self.override_users = set(x["name"] for x in js.get("overrideUsers", []))
        self.override_groups = set(x["name"] for x in js.get("overrideGroups", []))
        self.override_block = js.get("blockOverride", False)
        self.time_quota = js.get("timeQuota", 0)
        self.size_quota = js.get("sizeQuota", 0)
        self.validity_start_time = js.get("validityStartTime", 0)
        self.validity_end_time = js.get("validityEndTime", 0)
        self.validity_zone_id = js.get("validityTimeZoneId", "")
        self.last_modified_time = js.get("lastModifiedTime", 0)
        self.last_modified_by = js.get("lastModifiedBy", "")
        self.enforce_time_validity = js.get("enforceTimeValidity", False)
        self.cbi_profile = js.get("cbiProfile", {}).get("name", "")
        self.user_risk_score =  set(js.get("userRiskScoreLevels", []))
        self.source_countries = set(js.get("sourceCountries", []))


    def distance_from(self, url_rule: Self) -> float:
        """
            Define distance to another rule as the number of criteria that do not match.

            :param URLRule url_rule: Vector to compute distance to

            :return Real value of distance to vector
        """
        distance = 0

        distance += not self.action == url_rule.action
        distance += not self.state == url_rule.state
        distance += not self.src_ip_groups == url_rule.src_ip_groups
        distance += not self.src_ipv6_groups == url_rule.src_ipv6_groups
        distance += not self.locations == url_rule.locations
        distance += not self.location_groups == url_rule.location_groups
        distance += not self.users == url_rule.users
        distance += not self.user_groups == url_rule.user_groups
        distance += not self.user_devices == url_rule.user_devices
        distance += not self.user_device_groups == url_rule.user_device_groups
        distance += not self.device_trust_levels == url_rule.device_trust_levels
        distance += not self.departments == url_rule.departments
        distance += not self.url_categories == url_rule.url_categories
        distance += not self.user_agents == url_rule.user_agents
        distance += not self.protocols == url_rule.protocols
        distance += not self.request_methods == url_rule.request_methods
        distance += not self.time_window == url_rule.time_window
        distance += not self.workload_group == url_rule.workload_group
        distance += not self.notification_url == url_rule.notification_url
        distance += not self.override_users == url_rule.override_users
        distance += not self.override_groups == url_rule.override_groups
        distance += not self.override_block == url_rule.override_block
        distance += not self.time_quota == url_rule.time_quota
        distance += not self.size_quota == url_rule.size_quota
        distance += not self.validity_start_time == url_rule.validity_start_time
        distance += not self.validity_end_time == url_rule.validity_end_time
        distance += not self.validity_zone_id == url_rule.validity_zone_id
        distance += not self.last_modified_time == url_rule.last_modified_time
        distance += not self.last_modified_by == url_rule.last_modified_by
        distance += not self.enforce_time_validity == url_rule.enforce_time_validity
        distance += not self.cbi_profile == url_rule.cbi_profile
        distance += not self.user_risk_score == url_rule.user_risk_score
        distance += not self.source_countries == url_rule.source_countries


        return distance

    def _key(self) -> tuple:
        """
            Implement base abstract method. Order value is unique per rule – can be used as key.

            :return tuple[int]
        """
        return (self.order,)


class URLRuleWithSubsets(URLRule):
    """
        URLRule entity that checks whether rule A is a subset of rule B
        and vice versa.
    """

    def distance_from(self, url_rule: Self) -> float:
        """
            Define distance to another rule as a number of match criteria that do not
            match. If criterion of rule A is a subset of criterion from rule B, such
            a criterion does not contribute to the distance.

            Note: distance(A,B) != distance(B,A) in general case. However, triangle
            inequality is still satisfied (distance(A,C) < distance(A,B) + distance(B,C)),
            because the whole set is searched through.

            :param URLRule url_rule: Vector to compute distance to

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
            obj1 = self if i == 0 else url_rule
            obj2 = url_rule if i == 0 else self

            distance[i] += not obj1.action == obj2.action
            distance[i] += not obj1.state == obj2.state
            distance[i] += not obj1.notification_url == obj2.notification_url
            distance[i] += not obj1.override_block == obj2.override_block
            distance[i] += not obj1.time_quota == obj2.time_quota
            distance[i] += not obj1.size_quota == obj2.size_quota
            distance[i] += not obj1.validity_start_time == obj2.validity_start_time
            distance[i] += not obj1.validity_end_time == obj2.validity_end_time
            distance[i] += not obj1.validity_zone_id == obj2.validity_zone_id
            distance[i] += not obj1.enforce_time_validity == obj2.enforce_time_validity
            distance[i] += not obj1.cbi_profile == obj2.cbi_profile
            distance[i] += not is_subset(obj1.src_ip_groups, obj2.src_ip_groups)
            distance[i] += not is_subset(obj1.src_ipv6_groups, obj2.src_ipv6_groups)
            distance[i] += not is_subset(obj1.locations, obj2.locations)
            distance[i] += not is_subset(obj1.location_groups, obj2.location_groups)
            distance[i] += not is_subset(obj1.users, obj2.users)
            distance[i] += not is_subset(obj1.user_groups, obj2.user_groups)
            distance[i] += not is_subset(obj1.user_devices, obj2.user_devices)
            distance[i] += not is_subset(obj1.user_device_groups, obj2.user_device_groups)
            distance[i] += not is_subset(obj1.device_trust_levels, obj2.device_trust_levels)
            distance[i] += not is_subset(obj1.departments, obj2.departments)
            distance[i] += not is_subset(obj1.url_categories, obj2.url_categories)
            distance[i] += not is_subset(obj1.user_agents, obj2.user_agents)
            distance[i] += not is_subset(obj1.protocols, obj2.protocols)
            distance[i] += not is_subset(obj1.request_methods, obj2.request_methods)
            distance[i] += not is_subset(obj1.time_window, obj2.time_window)
            distance[i] += not is_subset(obj1.workload_group, obj2.workload_group)
            distance[i] += not is_subset(obj1.override_users, obj2.override_users)
            distance[i] += not is_subset(obj1.override_groups, obj2.override_groups)
            distance[i] += not is_subset(obj1.user_risk_score, obj2.user_risk_score)
            distance[i] += not is_subset(obj1.source_countries, obj2.source_countries)


        return min(distance)
