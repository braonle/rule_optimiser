# pylint: disable=E0402, R0903
""" Implement RuleOptimiser for ZIA Sandbox rules"""

from .optimiser import RuleOptimiser
from ..rules.sandbox_rule import SandboxRule, SandboxRuleWithSubsets


class SandboxOptimiser(RuleOptimiser):
    """
        Initialises rule list with ZIA Sandbox rules
    """

    def __init__(self, js_list: list[dict], search_subsets: bool = True):
        """
            Exclude default and pre-defined rules as those cannot be changed.

            :param list[dict]   js_list: list of FileType rules, decoded from JSON
        """
        super().__init__()

        if search_subsets:
            rule_class = SandboxRuleWithSubsets
        else:
            rule_class = SandboxRule

        self.rules = tuple(rule_class(x) for x in js_list)

        self._worksheet_fmt_name = "Sandbox distance {n}"
        self._rule_cls = SandboxRule
