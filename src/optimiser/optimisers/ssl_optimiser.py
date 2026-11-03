# pylint: disable=E0402, R0903
""" Implement RuleOptimiser for ZIA SSL rules"""

from .optimiser import RuleOptimiser
from ..rules.ssl_rule import SSLRule, SSLRuleWithSubsets


class SSLOptimiser(RuleOptimiser):
    """
        Initialises rule list with ZIA SSL rules
    """

    def __init__(self, js_list: list[dict], search_subsets: bool = True):
        """
            Exclude default and pre-defined rules as those cannot be changed.

            :param list[dict]   js_list: list of SSL rules, decoded from JSON
        """
        super().__init__()

        if search_subsets:
            rule_class = SSLRuleWithSubsets
        else:
            rule_class = SSLRule

        self.rules = tuple(rule_class(x) for x in js_list
                           if not x["defaultRule"] and not x.get("predefined", False))

        self._worksheet_fmt_name = "SSL distance {n}"
        self._rule_cls = SSLRule
