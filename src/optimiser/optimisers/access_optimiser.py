# pylint: disable=E0402, R0903
""" Implement RuleOptimiser for ZIA URL filtering rules"""

from .optimiser import RuleOptimiser
from ..rules.access_rule import AccessRule, AccessRuleWithSubsets


class AccessPolicyOptimiser(RuleOptimiser):
    """
        Initialises rule list with ZPA Access Policy rules
    """

    def __init__(self, js_list: list[dict], search_subsets: bool = True):
        """
            Exclude default and pre-defined rules as those cannot be changed.

            :param list[dict]   js_list: list of Access Policy rules, decoded from JSON
        """
        super().__init__()

        if search_subsets:
            rule_class = AccessRuleWithSubsets
        else:
            rule_class = AccessRule

        self.rules = tuple(rule_class(x) for x in js_list
                           if not x.get("defaultRule", False) and not x.get("predefined", False))

        self._worksheet_fmt_name = "Access Rule distance {n}"
        self._rule_cls = AccessRule
