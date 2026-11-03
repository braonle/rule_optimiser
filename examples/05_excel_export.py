# pylint: disable=E0401, C0413
"""
    Example 5 – export clusters to a spreadsheet for manual review.

    Run it with:  python examples/05_excel_export.py

    dsets_to_excel() writes one worksheet per distance, one row per rule, one column
    per rule attribute, with clusters separated by alternating fill colours and
    grouped into collapsible outline rows. An existing workbook is opened and added
    to rather than overwritten, so several policy types can share one file - which is
    what the second optimiser below does.

    Two things to keep in mind:

    * the method strips path separators out of both arguments, so "folder" must be a
      plain directory name next to the working directory, not a nested path;
    * worksheet names come from the optimiser's own prefix ("FW distance 0",
      "URL distance 0", ...), so re-running against the same workbook appends
      duplicate sheets rather than replacing them. A new workbook also carries the
      empty "Sheet" that openpyxl creates by default - delete it if it is in the way.
"""
import os

import _bootstrap  # noqa: F401  pylint: disable=W0611  (puts ./src on sys.path)

from optimiser import FirewallOptimiser
from optimiser.optimisers.url_optimiser import URLOptimiser

from sample_data import FIREWALL_RULES, URL_RULES

WORKBOOK = "clusters.xlsx"
THRESHOLD = 2


def main() -> None:
    """ Cluster two policy types and write both into the same workbook. """
    # Start from a clean file, otherwise the sheets of a previous run are kept
    if os.path.exists(WORKBOOK):
        os.remove(WORKBOOK)

    firewall = FirewallOptimiser(FIREWALL_RULES)
    firewall.get_dsets(THRESHOLD)
    firewall.dsets_to_excel(WORKBOOK)

    url = URLOptimiser(URL_RULES)
    url.get_dsets(THRESHOLD)
    url.dsets_to_excel(WORKBOOK)

    print(f"Wrote {os.path.abspath(WORKBOOK)}")

    # Read the result back to show what landed in the file
    import openpyxl as xl  # pylint: disable=C0415

    workbook = xl.load_workbook(WORKBOOK)
    for name in workbook.sheetnames:
        sheet = workbook[name]
        print(f"  sheet {name!r}: {sheet.max_row - 1} rule row(s), {sheet.max_column} column(s)")


if __name__ == "__main__":
    main()
