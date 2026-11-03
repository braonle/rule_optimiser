# pylint: disable=E0402, R0902, R0903
"""" Implements PolicyRule child class for ZPA Access Policy"""

from typing import Self, Callable

from .policy_rule import PolicyRule


class AccessRule(PolicyRule):
    """
        PolicyRule entity corresponds to a ZPA Access Policy rule entry

        Some parameters might be missing from the data, so their existence
        has to be checked before using. Lists are defined inconsistently either
        as attribute lists of sub-json lists, thus different processing
        (see "name" attribute assignment)
    """

    name: str = ""
    description: str = ""
    order: int = 0
    action: str = ""
    state: str = ""
    operator: str = ""
    extranetEnabled: bool = False
    app_connector_groups: set[str] = set()
    app_server_groups: set[str] = set()
    app_segments: set[str] = set()
    app_segment_groups: set[str] = set()
    client_types: set[str] = set()
    _posture: dict[set[str]] = {}
    user_groups: set[str] = set()
    _scim: dict[set[str]] = {}
    _saml: dict[set[str]] = {}
    machine_groups: set[str] = set()
    trusted_networks: set[str] = set()
    countries: set[str] = set()
    edge_connector_group: set[str] = set()
    branch_connector_group: set[str] = set()
    risk_factor_type: set[str] = set()
    location: set[str] = set()
    idps: set[str] = set()

    _SCIM_INDEX_STR = "SCIM {}"
    _SAML_INDEX_STR = "SAML {}"
    _POSTURE_INDEX_STR = "Posture {}"
    _scim_keys: set = set()
    _saml_keys: set = set()
    _posture_keys: set = set()

    def __init__(self, js):
        """
            Initialize object from a dictionary. JSON for ZPA Access Policy rule:
            https://help.zscaler.com/zpa/configuring-access-policies-using-api

            Note that some of the fields are missing from the documentation and have been
            reverse engineered from UI.

            :param json js: dictionary, built from ZPA API response without modification
        """
        self.name = js["name"]
        self.order = js["ruleOrder"]
        self.action = js["action"]
        self.description = js.get("description", "")
        self.state = "Enabled" if js["disabled"] == "0" else "Disabled"
        self.operator = js["operator"]
        self.extranetEnabled = js.get("extranetEnabled", "")
        self.app_connector_groups = set([x["name"] for x in js.get("assistantGroups", [])])
        self.app_server_groups = set([x["name"] for x in js.get("appServerGroups", [])])
        self._scim = {}
        self._saml = {}
        self._posture = {}
        self.app_segments = set()
        self.app_segment_groups = set()
        self.client_types = set()
        self.idps = set()
        self.user_groups = set()
        self.trusted_networks = set()
        self.machine_groups = set()
        self.countries = set()
        self.platforms = set()
        self.edge_connector_group = set()
        self.branch_connector_group = set()
        self.risk_factor_type = set()
        self.location = set()
        self.idps = set()

        for cond in js.get("conditions", []):
            for op in cond["operands"]:
                obj_type = op['objectType']
                obj_name = op.get('name', "")

                if obj_type == "APP":
                    self.app_segments.add(obj_name)
                elif obj_type == "APP_GROUP":
                    self.app_segment_groups.add(obj_name)
                elif obj_type == "CLIENT_TYPE":
                    self.client_types.add(obj_name)
                elif obj_type == "POSTURE":
                    self._posture[cond["operator"]] = self._posture.get(cond["operator"], set())
                    self._posture[cond["operator"]].add(f'{obj_name}={op["rhs"]}')
                elif obj_type == "SCIM":
                    self._scim[obj_name] = self._scim.get(obj_name, set())
                    self._scim[obj_name].add(op["rhs"])
                elif obj_type == "SAML":
                    self._saml[obj_name] = self._saml.get(obj_name, set())
                    self._saml[obj_name].add(op["rhs"])
                elif obj_type == "SCIM_GROUP":
                    self.user_groups.add(op["rhs"])
                elif obj_type == "TRUSTED_NETWORK":
                    self.trusted_networks.add(op["lhs"])
                elif obj_type == "MACHINE_GRP":
                    self.user_groups.add(op["rhs"])
                elif obj_type == "COUNTRY_CODE":
                    self.countries.add(obj_name)
                elif obj_type == "PLATFORM":
                    self.platforms.add(op["lhs"])
                elif obj_type == "EDGE_CONNECTOR_GROUP":
                    self.edge_connector_group.add(obj_name)
                elif obj_type == "BRANCH_CONNECTOR_GROUP":
                    self.branch_connector_group.add(obj_name)
                elif obj_type == "RISK_FACTOR_TYPE":
                    self.risk_factor_type.add(obj_name)
                elif obj_type == "LOCATION":
                    self.location.add(obj_name)
                elif obj_type == "IDP":
                    self.idps.add(obj_name)
                else:
                    raise ValueError(f"Unknown condition type within ZPA Access Policy {obj_type}")

        for key in self._scim.keys():
            index = AccessRule._SCIM_INDEX_STR.format(key)
            setattr(AccessRule, index, set())
            self.__dict__[index] = self._scim[key]
            AccessRule._scim_keys.add(index)

        for key in self._saml.keys():
            index = AccessRule._SAML_INDEX_STR.format(key)
            setattr(AccessRule, index, set())
            self.__dict__[index] = self._saml[key]
            AccessRule._saml_keys.add(index)

        for key in self._posture.keys():
            index = AccessRule._POSTURE_INDEX_STR.format(key)
            setattr(AccessRule, index, set())
            self.__dict__[index] = self._posture[key]
            AccessRule._posture_keys.add(index)

    def distance_from(self, access_rule: Self) -> float:
        """
            Define distance to another rule as the number of criteria that do not match.

            :param AccessRule access_rule: Vector to compute distance to

            :return Real value of distance to vector
        """
        distance = 0

        distance += not self.action == access_rule.action
        distance += not self.state == access_rule.state
        distance += not self.operator == access_rule.operator
        distance += not self.extranetEnabled == access_rule.extranetEnabled
        distance += not self.app_connector_groups == access_rule.app_connector_groups
        distance += not self.app_server_groups == access_rule.app_server_groups
        distance += not self.app_segments == access_rule.app_segments
        distance += not self.app_segment_groups == access_rule.app_segment_groups
        distance += not self.client_types == access_rule.client_types
        distance += not self.user_groups == access_rule.user_groups
        distance += not self.machine_groups == access_rule.machine_groups
        distance += not self.trusted_networks == access_rule.trusted_networks
        distance += not self.countries == access_rule.countries
        distance += not self.platforms == access_rule.platforms
        distance += not self.edge_connector_group == access_rule.edge_connector_group
        distance += not self.branch_connector_group == access_rule.branch_connector_group
        distance += not self.risk_factor_type == access_rule.risk_factor_type
        distance += not self.location == access_rule.location
        distance += not self.idps == access_rule.idps

        for key in AccessRule._scim_keys:
            distance += not self.__getattribute__(key) == access_rule.__getattribute__(key)

        for key in AccessRule._saml_keys:
            distance += not self.__getattribute__(key) == access_rule.__getattribute__(key)

        for key in AccessRule._posture_keys:
            distance += not self.__getattribute__(key) == access_rule.__getattribute__(key)

        return distance

    def _key(self) -> tuple:
        """
            Implement base abstract method. Order value is unique per rule – can be used as key.

            :return tuple[int]
        """
        return (self.order,)


class AccessRuleWithSubsets(AccessRule):
    """
        AccessRule entity that checks whether rule A is a subset of rule B
        and vice versa.
    """

    def distance_from(self, access_rule: Self) -> float:
        """
            Define distance to another rule as a number of match criteria that do not
            match. If criterion of rule A is a subset of criterion from rule B, such
            a criterion does not contribute to the distance.

            Note: distance(A,B) != distance(B,A) in general case. However, triangle
            inequality is still satisfied (distance(A,C) < distance(A,B) + distance(B,C)),
            because the whole set is searched through.

            :param AccessRule access_rule: Vector to compute distance to

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

        for i in range(0, 2):
            obj1 = self if i == 0 else access_rule
            obj2 = access_rule if i == 0 else self

            distance[i] += not obj1.action == obj2.action
            distance[i] += not obj1.state == obj2.state
            distance[i] += not obj1.operator == obj2.operator
            distance[i] += not obj1.extranetEnabled == obj2.extranetEnabled

            distance[i] += not is_subset(obj1.app_connector_groups, obj2.app_connector_groups)
            distance[i] += not is_subset(obj1.app_server_groups, obj2.app_server_groups)
            distance[i] += not is_subset(obj1.app_segments, obj2.app_segments)
            distance[i] += not is_subset(obj1.app_segment_groups, obj2.app_segment_groups)
            distance[i] += not is_subset(obj1.client_types, obj2.client_types)
            distance[i] += not is_subset(obj1.user_groups, obj2.user_groups)
            distance[i] += not is_subset(obj1.trusted_networks, obj2.trusted_networks)
            distance[i] += not is_subset(obj1.machine_groups, obj2.machine_groups)
            distance[i] += not is_subset(obj1.countries, obj2.countries)
            distance[i] += not is_subset(obj1.platforms, obj2.platforms)
            distance[i] += not is_subset(obj1.edge_connector_group, obj2.edge_connector_group)
            distance[i] += not is_subset(obj1.branch_connector_group, obj2.branch_connector_group)
            distance[i] += not is_subset(obj1.risk_factor_type, obj2.risk_factor_type)
            distance[i] += not is_subset(obj1.location, obj2.location)
            distance[i] += not is_subset(obj1.idps, obj2.idps)

            for key in AccessRule._scim_keys:
                distance[i] += not is_subset(obj1.__getattribute__(key), obj2.__getattribute__(key))

            for key in AccessRule._saml_keys:
                distance[i] += not is_subset(obj1.__getattribute__(key), obj2.__getattribute__(key))

            for key in AccessRule._posture_keys:
                distance[i] += not is_subset(obj1.__getattribute__(key), obj2.__getattribute__(key))

        return min(distance)
