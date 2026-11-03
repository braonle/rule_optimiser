# pylint: disable=E0402, R0903
""" Implement RuleOptimiser for ZIA URL filtering rules"""

from .optimiser import RuleOptimiser
from ..rules.url_rule import URLRule, URLRuleWithSubsets


class URLOptimiser(RuleOptimiser):
    """
        Initialises rule list with ZIA SSL rules
    """

    def __init__(self, js_list: list[dict], search_subsets: bool = True):
        """
            Exclude default and pre-defined rules as those cannot be changed.

            :param list[dict]   js_list: list of URL filtering rules, decoded from JSON
        """
        super().__init__()

        if search_subsets:
            rule_class = URLRuleWithSubsets
        else:
            rule_class = URLRule

        self.rules = tuple(rule_class(x) for x in js_list
                           if not x.get("defaultRule", False) and not x.get("predefined", False))

        self._worksheet_fmt_name = "URL distance {n}"
        self._rule_cls = URLRule
