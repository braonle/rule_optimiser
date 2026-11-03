# pylint: disable=E0402, R0902, R0903
"""" Implements PolicyRule child class for ZIA FW rules"""

from typing import Self, Callable

from .policy_rule import PolicyRule


class FirewallRule(PolicyRule):
    """
        FirewallRule entity corresponds to a ZIA FW rule entry

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
    src_addresses: set[str] = ()
    src_ip_groups: set[str] = ()
    src_ipv6_groups: set[str] = ()
    dest_addresses: set[str] = ()
    dest_ip_categories: set[str] = ()
    dest_ip_groups: set[str] = ()
    dest_ipv6_groups: set[str] = ()
    dest_countries: set[str] = ()
    src_countries: set[str] = ()
    network_services: set[str] = ()
    network_svc_groups: set[str] = ()
    network_applications: set[str] = ()
    network_app_groups: set[str] = ()
    app_service_groups: set[str] = ()
    locations: set[str] = ()
    location_groups: set[str] = ()
    users: set[str] = ()
    user_groups: set[str] = ()
    user_devices: set[str] = ()
    user_device_groups: set[str] = ()
    device_trust_levels: set[str] = ()
    departments: set[str] = ()
    zpa_app_segments: set[str] = ()

    def __init__(self, js):
        """
            Initialize object from a dictionary. JSON for ZIA FW rule:
            https://help.zscaler.com/zia/firewall-policies#/firewallFilteringRules-get

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
        self.src_addresses = set(js.get("srcIps", []))
        self.src_ip_groups = set(x["name"] for x in js.get("srcIpGroups", []))
        self.src_ipv6_groups = set(x["name"] for x in js.get("srcIpv6Groups", []))
        self.src_countries = set(js.get("sourceCountries", []))
        self.dest_addresses = set(js.get("destAddresses", []))
        self.dest_ip_categories = set(js.get("destIpCategories", []))
        self.dest_ip_groups = set(x["name"] for x in js.get("destIpGroups", []))
        self.dest_ipv6_groups = set(x["name"] for x in js.get("destIpv6Groups", []))
        self.dest_countries = set(js.get("destCountries", []))
        self.network_services = set(x["name"] for x in js.get("nwServices", []))
        self.network_svc_groups = set(x["name"] for x in js.get("nwServiceGroups", []))
        self.network_applications = set(js.get("nwApplications", []))
        self.network_app_groups = set(x["name"] for x in js.get("nwApplicationGroups", []))
        self.app_service_groups = set(x["name"] for x in js.get("appServiceGroups", []))
        self.locations = set(x["name"] for x in js.get("locations", []))
        self.location_groups = set(x["name"] for x in js.get("locationGroups", []))
        self.users = set(x["name"] for x in js.get("users", []))
        self.user_groups = set(x["name"] for x in js.get("groups", []))
        self.user_devices = set(x["name"] for x in js.get("devices", []))
        self.user_device_groups = set(x["name"] for x in js.get("deviceGroups", []))
        self.device_trust_levels = set(js.get("deviceTrustLevels", []))
        self.departments = set(x["name"] for x in js.get("departments", []))
        self.zpa_app_segments = set(x["name"] for x in js.get("zpaAppSegments", []))

    def distance_from(self, fw_rule: Self) -> float:
        """
            Define distance to another rule as the number of criteria that do not match.

            :param FirewallRule fw_rule: Vector to compute distance to

            :return Real value of distance to vector
        """
        distance = 0

        distance += not self.action == fw_rule.action
        distance += not self.state == fw_rule.state
        distance += not self.src_addresses == fw_rule.src_addresses
        distance += not self.src_ip_groups == fw_rule.src_ip_groups
        distance += not self.src_ipv6_groups == fw_rule.src_ipv6_groups
        distance += not self.src_countries == fw_rule.src_countries
        distance += not self.dest_addresses == fw_rule.dest_addresses
        distance += not self.dest_ip_categories == fw_rule.dest_ip_categories
        distance += not self.dest_ip_groups == fw_rule.dest_ip_groups
        distance += not self.dest_ipv6_groups == fw_rule.dest_ipv6_groups
        distance += not self.dest_countries == fw_rule.dest_countries
        distance += not self.network_services == fw_rule.network_services
        distance += not self.network_svc_groups == fw_rule.network_svc_groups
        distance += not self.network_applications == fw_rule.network_applications
        distance += not self.network_app_groups == fw_rule.network_app_groups
        distance += not self.app_service_groups == fw_rule.app_service_groups
        distance += not self.locations == fw_rule.locations
        distance += not self.location_groups == fw_rule.location_groups
        distance += not self.users == fw_rule.users
        distance += not self.user_groups == fw_rule.user_groups
        distance += not self.user_devices == fw_rule.user_devices
        distance += not self.user_device_groups == fw_rule.user_device_groups
        distance += not self.device_trust_levels == fw_rule.device_trust_levels
        distance += not self.departments == fw_rule.departments
        distance += not self.zpa_app_segments == fw_rule.zpa_app_segments

        return distance

    def _key(self) -> tuple:
        """
            Implement base abstract method. Order value is unique per rule – can be used as key.

            :return tuple[int]
        """
        return (self.order,)


class FirewallRuleWithSubsets(FirewallRule):
    """
        FirewallRule entity that checks whether rule A is a subset of rule B
        and vice versa.
    """

    def distance_from(self, fw_rule: Self) -> float:
        """
            Define distance to another rule as a number of match criteria that do not
            match. If criterion of rule A is a subset of criterion from rule B, such
            a criterion does not contribute to the distance.

            Note: distance(A,B) != distance(B,A) in general case. However, triangle
            inequality is still satisfied (distance(A,C) < distance(A,B) + distance(B,C)),
            because the whole set is searched through.

            :param FirewallRule fw_rule: Vector to compute distance to

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
            obj1 = self if i == 0 else fw_rule
            obj2 = fw_rule if i == 0 else self

            distance[i] += not obj1.action == obj2.action
            distance[i] += not obj1.state == obj2.state
            distance[i] += not is_subset(obj1.src_addresses, obj2.src_addresses)
            distance[i] += not is_subset(obj1.src_ip_groups, obj2.src_ip_groups)
            distance[i] += not is_subset(obj1.src_ipv6_groups, obj2.src_ipv6_groups)
            distance[i] += not is_subset(obj1.src_countries, obj2.src_countries)
            distance[i] += not is_subset(obj1.dest_addresses, obj2.dest_addresses)
            distance[i] += not is_subset(obj1.dest_ip_categories, obj2.dest_ip_categories)
            distance[i] += not is_subset(obj1.dest_ip_groups, obj2.dest_ip_groups)
            distance[i] += not is_subset(obj1.dest_ipv6_groups, obj2.dest_ipv6_groups)
            distance[i] += not is_subset(obj1.dest_countries, obj2.dest_countries)
            distance[i] += not is_subset(obj1.network_services, obj2.network_services)
            distance[i] += not is_subset(obj1.network_svc_groups, obj2.network_svc_groups)
            distance[i] += not is_subset(obj1.network_applications, obj2.network_applications)
            distance[i] += not is_subset(obj1.network_app_groups, obj2.network_app_groups)
            distance[i] += not is_subset(obj1.app_service_groups, obj2.app_service_groups)
            distance[i] += not is_subset(obj1.locations, obj2.locations)
            distance[i] += not is_subset(obj1.location_groups, obj2.location_groups)
            distance[i] += not is_subset(obj1.users, obj2.users)
            distance[i] += not is_subset(obj1.user_groups, obj2.user_groups)
            distance[i] += not is_subset(obj1.user_devices, obj2.user_devices)
            distance[i] += not is_subset(obj1.user_device_groups, obj2.user_device_groups)
            distance[i] += not is_subset(obj1.device_trust_levels, obj2.device_trust_levels)
            distance[i] += not is_subset(obj1.departments, obj2.departments)
            distance[i] += not is_subset(obj1.zpa_app_segments, obj2.zpa_app_segments)

        return min(distance)
