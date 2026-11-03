# pylint: disable=E0401, C0413, R0903
"""
    Example 7 – support a policy type the library does not ship with.

    Run it with:  python examples/07_custom_rule_type.py

    The library covers Firewall, URL Filtering, SSL Inspection, File Type Control,
    Sandbox and ZPA Access Policy. Anything else - here ZIA DLP Web rules - is added
    by writing two small classes; none of the clustering logic has to be touched.

    A PolicyRule subclass has to provide:

      __init__        turn one API dictionary into attributes
      distance_from   count the criteria that do not match
      _key            a tuple that identifies the rule, used for hashing and equality

    A RuleOptimiser subclass only has to populate self.rules and declare two names:

      _rule_cls             the class whose attributes become the Excel columns
      _worksheet_fmt_name   the worksheet title, with an {n} placeholder for distance

    Class-level attributes are not decoration: dsets_to_excel() reads them off
    _rule_cls to work out the columns, and anything starting with "_" is skipped.
"""
from typing import Self

import _bootstrap  # noqa: F401  pylint: disable=W0611  (puts ./src on sys.path)

from optimiser import RuleOptimiser
from optimiser.rules.policy_rule import PolicyRule

from reporting import print_clusters

THRESHOLD = 2


class DLPRule(PolicyRule):
    """ One ZIA DLP Web rule. """

    name: str = ""
    description: str = ""
    order: int = 0
    action: str = ""
    state: str = ""
    dlp_engines: set[str] = ()
    locations: set[str] = ()
    user_groups: set[str] = ()
    file_types: set[str] = ()
    severity: str = ""

    def __init__(self, js: dict):
        """
            Initialise from an API dictionary.

            Only "name" and "order" are mandatory in practice - optional criteria are
            absent from the response rather than empty, so read them with .get().

            :param dict js: one rule, decoded from the API response
        """
        self.name = js["name"]
        self.order = js["order"]
        self.action = js["action"]
        self.state = js["state"]
        self.description = js.get("description", "")
        self.dlp_engines = set(x["name"] for x in js.get("dlpEngines", []))
        self.locations = set(x["name"] for x in js.get("locations", []))
        self.user_groups = set(x["name"] for x in js.get("groups", []))
        self.file_types = set(js.get("fileTypes", []))
        self.severity = js.get("severity", "")

    def distance_from(self, dlp_rule: Self) -> float:
        """
            Distance is the number of criteria that differ. Only the criteria that
            decide whether two rules could be merged belong here - name, description
            and order are descriptive and are deliberately left out.

            :param DLPRule dlp_rule: rule to compute the distance to

            :return Real value of distance to the rule
        """
        distance = 0

        distance += not self.action == dlp_rule.action
        distance += not self.state == dlp_rule.state
        distance += not self.dlp_engines == dlp_rule.dlp_engines
        distance += not self.locations == dlp_rule.locations
        distance += not self.user_groups == dlp_rule.user_groups
        distance += not self.file_types == dlp_rule.file_types
        distance += not self.severity == dlp_rule.severity

        return distance

    def _key(self) -> tuple:
        """
            Order is unique per rule, so it identifies the rule on its own.

            :return tuple[int]
        """
        return (self.order,)


class DLPOptimiser(RuleOptimiser):
    """ Cluster ZIA DLP Web rules. """

    def __init__(self, js_list: list[dict]):
        """
            :param list[dict] js_list: DLP rules, decoded from the API response
        """
        super().__init__()

        self.rules = tuple(DLPRule(x) for x in js_list if not x.get("defaultRule", False))

        self._worksheet_fmt_name = "DLP distance {n}"
        self._rule_cls = DLPRule


DLP_RULES: list[dict] = [
    {
        "name": "Block PCI uploads - EMEA",
        "order": 1,
        "action": "BLOCK",
        "state": "ENABLED",
        "severity": "RULE_SEVERITY_HIGH",
        "dlpEngines": [{"id": 1, "name": "PCI"}],
        "locations": [{"id": 201, "name": "Paris HQ"}],
    },
    {
        "name": "Block PCI uploads - AMER",
        "order": 2,
        "action": "BLOCK",
        "state": "ENABLED",
        "severity": "RULE_SEVERITY_HIGH",
        "dlpEngines": [{"id": 1, "name": "PCI"}],
        "locations": [{"id": 202, "name": "New York HQ"}],
    },
    {
        "name": "Block PCI uploads - APAC",
        "order": 3,
        "action": "BLOCK",
        "state": "ENABLED",
        "severity": "RULE_SEVERITY_HIGH",
        "dlpEngines": [{"id": 1, "name": "PCI"}],
        "locations": [{"id": 203, "name": "Tokyo HQ"}],
    },
    {
        "name": "Audit source code",
        "order": 4,
        "action": "ALLOW",
        "state": "ENABLED",
        "severity": "RULE_SEVERITY_LOW",
        "dlpEngines": [{"id": 2, "name": "Source Code"}],
    },
]


def main() -> None:
    """ Cluster the custom rule type and show the JSON export works too. """
    optimiser = DLPOptimiser(DLP_RULES)

    print_clusters(optimiser.get_dsets(THRESHOLD), "ZIA DLP Web clusters")

    document = optimiser.dsets_to_dict()
    print("\nThe generic exports work unchanged:")
    for entry in document["clusters"]:
        for cluster in entry["cluster_list"]:
            names = sorted(rule["name"] for rule in cluster)
            print(f"  distance {entry['distance']}: {names}")


if __name__ == "__main__":
    main()
