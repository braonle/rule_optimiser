# pylint: disable=E0401, C0413
"""
    Example 3 – search_subsets: exact match or containment?

    Run it with:  python examples/03_subsets_vs_exact.py

    Every optimiser takes search_subsets (default True), which decides how a single
    match criterion is compared:

      search_subsets=False   the criteria must be equal, otherwise the distance grows
      search_subsets=True    if A's criterion is contained in B's, it costs nothing

    Containment is what makes redundant rules visible. "Block TOR" matches TOR while
    "Block anonymisers" matches TOR and ULTRASURF, so the first rule adds nothing the
    second does not already cover - distance 0 with subsets, distance 1 without.

    Note that an empty criterion means "any", so it is treated as the widest possible
    superset: "Allow NTP - Global" has no locations and therefore contains all of the
    location-scoped rules.
"""
import _bootstrap  # noqa: F401  pylint: disable=W0611  (puts ./src on sys.path)

from optimiser import FirewallOptimiser

from reporting import print_clusters
from sample_data import FIREWALL_RULES

THRESHOLD = 2


def rule_by_name(optimiser: FirewallOptimiser, name: str):
    """ Look a rule up by its name, for the pair-wise comparison below. """
    return next(rule for rule in optimiser.rules if rule.name == name)


def main() -> None:
    """ Build the same policy twice and compare the two interpretations. """
    exact = FirewallOptimiser(FIREWALL_RULES, search_subsets=False)
    subsets = FirewallOptimiser(FIREWALL_RULES, search_subsets=True)

    pair = ("Block TOR", "Block anonymisers")

    for label, optimiser in (("search_subsets=False", exact), ("search_subsets=True", subsets)):
        left = rule_by_name(optimiser, pair[0])
        right = rule_by_name(optimiser, pair[1])
        print(f"{label:>22}: distance({pair[0]!r}, {pair[1]!r}) = {left.distance_from(right)}")

    print_clusters(exact.get_dsets(THRESHOLD), "Exact match (search_subsets=False)")
    print_clusters(subsets.get_dsets(THRESHOLD), "Containment (search_subsets=True)")


if __name__ == "__main__":
    main()
