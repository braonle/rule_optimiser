# pylint: disable=E0402, R0903
""" Implement RuleOptimiser for ZIA FileType rules"""

from .optimiser import RuleOptimiser
from ..rules.filetype_rule import FileTypeRule, FileTypeRuleWithSubsets


class FileTypeOptimiser(RuleOptimiser):
    """
        Initialises rule list with ZIA FileType rules
    """

    def __init__(self, js_list: list[dict], search_subsets: bool = True):
        """
            Exclude default and pre-defined rules as those cannot be changed.

            :param list[dict]   js_list: list of FileType rules, decoded from JSON
        """
        super().__init__()

        if search_subsets:
            rule_class = FileTypeRuleWithSubsets
        else:
            rule_class = FileTypeRule

        self.rules = tuple(rule_class(x) for x in js_list)

        self._worksheet_fmt_name = "File distance {n}"
        self._rule_cls = FileTypeRule
