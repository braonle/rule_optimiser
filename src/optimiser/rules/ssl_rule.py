# pylint: disable=E0402, R0902, R0903
"""" Implements PolicyRule child class for ZIA SSL rules"""

from typing import Self, Callable

from .policy_rule import PolicyRule


class ActionTypes:
    """
        Static class with consts for actions within SSL rule.
        Used to select the necessary JSON key for pulling the parameters of the action.
    """
    DO_NOT_DECRYPT = "DO_NOT_DECRYPT"
    DECRYPT = "DECRYPT"
    BLOCK = "BLOCK"


class SSLRule(PolicyRule):
    """
        PolicyRule entity corresponds to a ZIA SSL rule entry

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
    dest_ip_groups: set[str] = ()
    dest_ipv6_groups: set[str] = ()
    locations: set[str] = ()
    location_groups: set[str] = ()
    users: set[str] = ()
    user_groups: set[str] = ()
    user_devices: set[str] = ()
    user_device_groups: set[str] = ()
    device_trust_levels: set[str] = ()
    departments: set[str] = ()
    zpa_app_segments: set[str] = ()
    zpa_gateway: set[str] = ()
    url_categories: set[str] = ()
    cloud_apps: set[str] = ()
    platforms: set[str] = ()
    user_agents: set[str] = ()
    kerberos_rw: bool = False
    override_default_cert: bool = False
    show_eun: bool = False
    oscp_check: bool = False
    bypass_other_policies: bool = False
    untrusted_certs: str = ""
    min_client_tls: str = ""
    min_server_tls: str = ""
    block_undecrypt: bool = False
    http2_enabled: bool = False


    def __init__(self, js):
        """
            Initialize object from a dictionary. SSL API is not published, has to be
            reversed from ZSUI calls using any web browser (JS calls the APIs)

            :param json js: dictionary, built from ZSUI reverse engineering
        """
        self.name = js["name"]
        self.order = js["order"]
        self.rank = js["rank"]
        self.action = js["action"]["type"]
        self.state = js["state"]
        self.description = js.get("description", "")
        self.labels = set(x["name"] for x in js.get("labels", []))
        self.src_ip_groups = set(x["name"] for x in js.get("sourceIpGroups", []))
        self.src_ipv6_groups = set(x["name"] for x in js.get("sourceIpv6Groups", []))
        self.dest_ip_groups = set(x["name"] for x in js.get("destIpGroups", []))
        self.dest_ipv6_groups = set(x["name"] for x in js.get("destIpv6Groups", []))
        self.locations = set(x["name"] for x in js.get("locations", []))
        self.location_groups = set(x["name"] for x in js.get("locationGroups", []))
        self.users = set(x["name"] for x in js.get("users", []))
        self.user_groups = set(x["name"] for x in js.get("groups", []))
        self.user_devices = set(x["name"] for x in js.get("devices", []))
        self.user_device_groups = set(x["name"] for x in js.get("deviceGroups", []))
        self.device_trust_levels = set(js.get("deviceTrustLevels", []))
        self.departments = set(x["name"] for x in js.get("departments", []))
        self.zpa_app_segments = set(x["name"] for x in js.get("zpaAppSegments", []))
        self.zpa_gateway = set(x["name"] for x in js.get("zpaGateway", []))
        self.url_categories = set(js.get("urlCategories", []))
        self.cloud_apps = set(js.get("cloudApplications", []))
        self.platforms = set(js.get("platforms", []))
        self.user_agents = set(js.get("userAgentTypes", []))
        self.kerberos_rw = js.get("roadWarriorForKerberos", False)
        self.override_default_cert = js["action"].get("overrideDefaultCertificate", False)
        self.show_eun = js["action"].get("showEUN", False)

        action_subsection = {}
        if self.action == ActionTypes.DO_NOT_DECRYPT:
            action_subsection = js["action"]["doNotDecryptSubActions"]
        elif self.action == ActionTypes.DECRYPT:
            action_subsection = js["action"]["decryptSubActions"]

        self.bypass_other_policies = action_subsection.get("bypassOtherPolicies", False)
        self.oscp_check = action_subsection.get("ocspCheck", False)
        self.untrusted_certs = action_subsection.get("serverCertificates", False)
        self.min_client_tls = action_subsection.get("minClientTLSVersion", False)
        self.min_server_tls = action_subsection.get("minServerTLSVersion", False)
        self.block_undecrypt = action_subsection.get("blockUndecrypt", False)
        self.http2_enabled = action_subsection.get("http2Enabled", False)

    def distance_from(self, ssl_rule: Self) -> float:
        """
            Define distance to another rule as the number of criteria that do not match.

            :param SSLRule ssl_rule: Vector to compute distance to

            :return Real value of distance to vector
        """
        distance = 0

        distance += not self.action == ssl_rule.action
        distance += not self.state == ssl_rule.state
        distance += not self.src_ip_groups == ssl_rule.src_ip_groups
        distance += not self.src_ipv6_groups == ssl_rule.src_ipv6_groups
        distance += not self.dest_ip_groups == ssl_rule.dest_ip_groups
        distance += not self.dest_ipv6_groups == ssl_rule.dest_ipv6_groups
        distance += not self.locations == ssl_rule.locations
        distance += not self.location_groups == ssl_rule.location_groups
        distance += not self.users == ssl_rule.users
        distance += not self.user_groups == ssl_rule.user_groups
        distance += not self.user_devices == ssl_rule.user_devices
        distance += not self.user_device_groups == ssl_rule.user_device_groups
        distance += not self.device_trust_levels == ssl_rule.device_trust_levels
        distance += not self.departments == ssl_rule.departments
        distance += not self.zpa_app_segments == ssl_rule.zpa_app_segments
        distance += not self.zpa_gateway == ssl_rule.zpa_gateway
        distance += not self.url_categories == ssl_rule.url_categories
        distance += not self.cloud_apps == ssl_rule.cloud_apps
        distance += not self.platforms == ssl_rule.platforms
        distance += not self.user_agents == ssl_rule.user_agents
        distance += not self.kerberos_rw == ssl_rule.kerberos_rw
        distance += not self.override_default_cert == ssl_rule.override_default_cert
        distance += not self.show_eun == ssl_rule.show_eun
        distance += not self.bypass_other_policies == ssl_rule.bypass_other_policies
        distance += not self.oscp_check == ssl_rule.oscp_check
        distance += not self.untrusted_certs == ssl_rule.untrusted_certs
        distance += not self.min_client_tls == ssl_rule.min_client_tls
        distance += not self.min_server_tls == ssl_rule.min_server_tls
        distance += not self.block_undecrypt == ssl_rule.block_undecrypt
        distance += not self.http2_enabled == ssl_rule.http2_enabled

        return distance

    def _key(self) -> tuple:
        """
            Implement base abstract method. Order value is unique per rule – can be used as key.

            :return tuple[int]
        """
        return (self.order,)


class SSLRuleWithSubsets(SSLRule):
    """
        SSLRule entity that checks whether rule A is a subset of rule B
        and vice versa.
    """

    def distance_from(self, ssl_rule: Self) -> float:
        """
            Define distance to another rule as a number of match criteria that do not
            match. If criterion of rule A is a subset of criterion from rule B, such
            a criterion does not contribute to the distance.

            Note: distance(A,B) != distance(B,A) in general case. However, triangle
            inequality is still satisfied (distance(A,C) < distance(A,B) + distance(B,C)),
            because the whole set is searched through.

            :param SSLRule ssl_rule: Vector to compute distance to

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
            obj1 = self if i == 0 else ssl_rule
            obj2 = ssl_rule if i == 0 else self

            distance[i] += not obj1.action == obj2.action
            distance[i] += not obj1.state == obj2.state
            distance[i] += not obj1.kerberos_rw == obj2.kerberos_rw
            distance[i] += not obj1.override_default_cert == obj2.override_default_cert
            distance[i] += not obj1.show_eun == obj2.show_eun
            distance[i] += not obj1.oscp_check == obj2.oscp_check
            distance[i] += not obj1.bypass_other_policies == obj2.bypass_other_policies
            distance[i] += not obj1.untrusted_certs == obj2.untrusted_certs
            distance[i] += not obj1.min_client_tls == obj2.min_client_tls
            distance[i] += not obj1.min_server_tls == obj2.min_server_tls
            distance[i] += not obj1.block_undecrypt == obj2.block_undecrypt
            distance[i] += not obj1.http2_enabled == obj2.http2_enabled
            distance[i] += not is_subset(obj1.src_ip_groups, obj2.src_ip_groups)
            distance[i] += not is_subset(obj1.src_ipv6_groups, obj2.src_ipv6_groups)
            distance[i] += not is_subset(obj1.dest_ip_groups, obj2.dest_ip_groups)
            distance[i] += not is_subset(obj1.dest_ipv6_groups, obj2.dest_ipv6_groups)
            distance[i] += not is_subset(obj1.locations, obj2.locations)
            distance[i] += not is_subset(obj1.location_groups, obj2.location_groups)
            distance[i] += not is_subset(obj1.users, obj2.users)
            distance[i] += not is_subset(obj1.user_groups, obj2.user_groups)
            distance[i] += not is_subset(obj1.user_devices, obj2.user_devices)
            distance[i] += not is_subset(obj1.user_device_groups, obj2.user_device_groups)
            distance[i] += not is_subset(obj1.device_trust_levels, obj2.device_trust_levels)
            distance[i] += not is_subset(obj1.departments, obj2.departments)
            distance[i] += not is_subset(obj1.zpa_app_segments, obj2.zpa_app_segments)
            distance[i] += not is_subset(obj1.zpa_gateway, obj2.zpa_gateway)
            distance[i] += not is_subset(obj1.url_categories, obj2.url_categories)
            distance[i] += not is_subset(obj1.cloud_apps, obj2.cloud_apps)
            distance[i] += not is_subset(obj1.platforms, obj2.platforms)
            distance[i] += not is_subset(obj1.user_agents, obj2.user_agents)

        return min(distance)
