# pylint: disable=E0401, C0413
"""
    Example 2 – pick a threshold before computing clusters.

    Run it with:  python examples/02_distance_distribution.py

    get_dsets() has to be told how far apart two rules may be before they stop being
    "similar enough". Guessing is wasteful: a threshold that is too low finds nothing
    and one that is too high puts every rule in one cluster.

    get_distance_distribution() answers the question up front. It walks every pair of
    rules once and counts how often each distance occurs, so the most common distance
    plus one is a sensible first threshold to try.
"""
import _bootstrap  # noqa: F401  pylint: disable=W0611  (puts ./src on sys.path)

from optimiser import FirewallOptimiser

from sample_data import FIREWALL_RULES


def main() -> None:
    """ Print the pair-wise distance histogram and derive a threshold from it. """
    optimiser = FirewallOptimiser(FIREWALL_RULES)

    distribution = optimiser.get_distance_distribution()
    pairs = sum(distribution.values())

    print(f"Pair-wise distances over {len(optimiser.rules)} rules ({pairs} pairs)\n")
    print(f"{'distance':>8}  {'pairs':>5}  histogram")

    for distance in sorted(distribution):
        count = distribution[distance]
        print(f"{distance:>8}  {count:>5}  {'#' * count}")

    # The most common distance is the one that separates most of the policy;
    # +1 turns it into a threshold, since get_dsets() excludes the upper bound.
    most_common = max(distribution, key=distribution.get)
    threshold = most_common + 1

    print(f"\nMost common distance: {most_common} -> suggested threshold: {threshold}")

    dsets = optimiser.get_dsets(threshold)
    found = sum(len(clusters) for clusters in dsets)

    print(f"get_dsets({threshold}) returns {found} cluster(s) across distances 0..{threshold - 1}")


if __name__ == "__main__":
    main()
