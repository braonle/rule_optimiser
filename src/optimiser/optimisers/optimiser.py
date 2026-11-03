# pylint: disable=E0402
""" Base class to find sets of similar rules. """
import os
from functools import reduce

import openpyxl as xl
import openpyxl.styles as xlstyle

from ..rules.policy_rule import PolicyRule


class RuleOptimiser:
    """
        Base class to find sets of similar rules. Child classes are expected to implement
        initialisation methods only.

        The idea is the following:
        1. Create list of sets with a single element per rule: [x1, x2, ...] -> [(x1), (x2), ...]
        2. Try adding each element of rule list to each set, verifying distance

        If a correct set S exists, it can and will be constructed by the procedure above.
        Single rule can be part of several output sets.
    """

    rules: tuple[PolicyRule] = ()
    dsets = []
    _worksheet_fmt_name: str = "Distance {n}"
    _rule_cls = None  # Used by Excel formatting, child classes are to assign Class values

    def _get_sets_for_distance(self, distance: int, sets: list[set[PolicyRule]],
                               distance_mapper: dict[PolicyRule, dict[PolicyRule, float]] = None) \
            -> list[set[PolicyRule]]:
        """
            Private method. Find sets of rules that do not exceed predefined distance
            within the set.

            :param int                  distance: max distance within set of rules
            :param list[set[PolicyRule] sets: input sets, potentially from previous iteration
            :param dict[PolicyRule, dict[PolicyRule, float]] distance_mapper: pairwise
                    pre-computed distances

            :return list[set[PolicyRule]] lists of sets, satisfying distance requirement
        """

        for rule in self.rules:
            # If rule is already present in the current set – continue the loop
            # Such overlap is expected to happen due to how initial list of sets is constructed.
            for st in sets:
                if rule in st:
                    continue

                dist: float = rule.distance_to_set(st, distance, distance_mapper)
                if dist <= distance:
                    st.add(rule)

            # Remove duplicates
            sets = reduce(lambda lst, elem: lst + [elem] if elem not in lst else lst, sets, [])

        return sets

    def get_dsets(self, threshold: int) -> list[list[set[PolicyRule]]]:
        """
            Public method. Find sets of rules that do not exceed threshold within the set.
            Distances are iterated over with the step of 1, threshold excluded.

            Levels of the output:
            1.  The distance the sets are computed for (e.g., result[0] returns lists of sets
                with distance less than or equal 0.
            2.  Cluster index for the distance (e.g., result[0][0] returns the set of rules
                for the first cluster with distance equal to 0

            :param int  threshold: max distance within sets of rules

            :return list[list[set[PolicyRule]]] List of cluster lists, indexed by distance
        """
        sets: list[set[PolicyRule]] = []
        output_set = []

        # Pre-compute pair wise distances
        distance_mapper: dict[PolicyRule, dict[PolicyRule, float]] = {}
        for x in self.rules:
            distance_mapper[x] = {}
            for y in self.rules:
                distance_mapper[x][y] = x.distance_from(y)

        # Initialize list of sets with sets of single item per rule
        for rule in self.rules:
            sets.append({rule})

        # Compute clusters for each distance
        for distance in range(0, threshold):
            sets = self._get_sets_for_distance(distance, sets, distance_mapper)

            # Exclude rules from output that should have already been added on previous iteration.
            # Exclude degenerate sets of single element.
            # It's important to copy sets due to "pass by reference" approach in Python.
            output_set.append(
                [x.copy() for x in sets
                 if (len(x) > 1) and (PolicyRule.distance_within_set(x) > distance - 1)])

        self.dsets = output_set.copy()

        return output_set

    def get_distance_distribution(self) -> dict[int, int]:
        """
            Calculate pair-wise distribution of distances within rule list.
            Can be used to find the most common distance between the rules and use it
            as threshold (distance + 1)

            :return dict[int, int]  Dictionary of { distance : count }
        """

        length = len(self.rules)
        distr = {}

        # Iterate from first rule till penultimate rule
        for i in range(0, length - 1):

            # Iterate from current till ultimate rule
            for j in range(i + 1, length):
                distance = self.rules[i].distance_from(self.rules[j])

                distr[distance] = distr.get(distance, 0) + 1

        return distr

    def dsets_to_dict(self) -> dict[str, list[dict]]:
        """
            Convert internal list of clusters to dictionary.

            :return dict[str]   JSON representation of clusters
        """

        result = {
            "clusters": []
        }

        # Iterate over distances
        for i, clusters in enumerate(self.dsets):
            sets = []

            # Iterate over clusters for distance
            for cluster in clusters:
                rules = []

                # Iterate over rules within cluster
                for rule in cluster:
                    rules.append(rule.to_dict())

                sets.append(rules)

            result["clusters"].append({
                "distance": i,
                "cluster_list": sets
            })

        return result

    def dsets_to_excel(self, filename: str, folder: str = ".") -> None:
        """
            Convert internal list of clusters to Excel spreadsheet.

            :param str     filename: path to Excel file, either new or existing
            :param str     folder: path to folder with Excel file

            :return dict[str]   JSON representation of clusters
        """
        cluster_heading: str = "cluster_number"
        column_width = 25

        # Input cleanup
        filepath = "".join(i for i in filename if i not in r'\/:*?"<>|')
        folderpath = "".join(i for i in folder if i not in r'\/:*?"<>|')
        xls_file = os.path.join(folderpath, filepath)

        # Try opening the existing Excel, if fail – create a new one
        try:
            wb: xl.Workbook = xl.load_workbook(filename=xls_file)
        except FileNotFoundError:
            wb: xl.Workbook = xl.Workbook()

        # Prepare common settings for each worksheet
        ws_heading = [cluster_heading]
        cls_keys = []

        # Find attributes to be used as columns from PolicyRule class instance,
        # excluding internal attributes and functions
        for attribute in self._rule_cls.__dict__:
            if attribute[:2] != '__' and attribute[0] != '_':
                value = getattr(self._rule_cls, attribute)
                if not callable(value):
                    cls_keys.append(attribute)

        ws_heading.extend(cls_keys)

        # Alternate cell colours between clusters for visual aid
        color_fills = [
            xlstyle.PatternFill(patternType='solid', fgColor=xlstyle.colors.Color(rgb='EBF1DE')),
            xlstyle.PatternFill(patternType='solid', fgColor=xlstyle.colors.Color(rgb='F2DCDB')),
            xlstyle.PatternFill(patternType='solid', fgColor=xlstyle.colors.Color(rgb='DAEEF3'))
        ]

        cell_style = xlstyle.Alignment(wrap_text=True, vertical="center")

        # Iterate over distances
        for i, clusters in enumerate(self.dsets):
            # Create a new worksheet for every distance
            ws_name = self._worksheet_fmt_name.format(n=i)
            wb.create_sheet(ws_name)
            ws = wb[ws_name]

            # Fill out the heading how and set column width
            for col, val in enumerate(ws_heading, start=1):
                ws.cell(row=1, column=col).value = val
                if col < 27:
                    col_name = chr(ord('A') + col - 1)
                else:
                    col_name = chr(ord('A') + (col - 26) // 26) + chr(ord('A') + (col - 26) % 26)

                ws.column_dimensions[col_name].width = column_width

            row = 2
            # Iterate over clusters
            for j, cluster in enumerate(clusters, start=1):

                # Iterate over rules within the cluster
                for k, rule in enumerate(cluster):
                    # Fill CLUSTER_HEADING cell
                    cell = ws.cell(row=row+k, column=1)
                    cell.value = j
                    cell.fill = color_fills[j % len(color_fills)]
                    cell.alignment = cell_style

                    # Fill class cells
                    d = rule.to_dict()
                    for col, key in enumerate(cls_keys, start=2):
                        cell = ws.cell(row+k, column=col)
                        value = str(d.get(key, ""))
                        cell.value = value if value != "set()" else "()"
                        cell.fill = color_fills[j % len(color_fills)]
                        cell.alignment = cell_style

                ws.row_dimensions.group(row, row + len(cluster) - 2, outline_level=2)
                row += len(cluster)

            # Create filter from top column and freeze it
            if len(cls_keys) < 26:
                flt = ''.join(("A1:", chr(ord('A') + len(cls_keys)), str(row)))
            else:
                flt = ''.join(("A1:",
                                  chr(ord('A') + (len(cls_keys) - 26) // 26),
                                  chr(ord('A') + (len(cls_keys) - 26) % 26),
                                  str(row)))

            ws.auto_filter.ref = flt
            ws.freeze_panes = "C2"

        wb.save(xls_file)
