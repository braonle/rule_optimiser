# pylint: disable=E0402, R0903
""" Implement RuleOptimiser for ZIA FW rules"""

from .optimiser import RuleOptimiser
from ..rules.firewall_rule import FirewallRule, FirewallRuleWithSubsets


class FirewallOptimiser(RuleOptimiser):
    """
        Initialises rule list with ZIA FW rules
    """

    def __init__(self, js_list: list[dict], search_subsets: bool = True):
        """
            Exclude default and pre-defined rules as those cannot be changed.

            :param list[dict]   js_list: list of firewall rules, decoded from JSON
        """
        super().__init__()

        if search_subsets:
            rule_class = FirewallRuleWithSubsets
        else:
            rule_class = FirewallRule

        self.rules = tuple(rule_class(x) for x in js_list
                           if not x["defaultRule"] and "predefined" not in x)

        self._worksheet_fmt_name = "FW distance {n}"
        self._rule_cls = FirewallRule
