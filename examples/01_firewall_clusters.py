# pylint: disable=E0401, C0413
"""
    Example 1 – find clusters of similar ZIA Firewall Control rules.

    Run it with:  python examples/01_firewall_clusters.py

    Expected output: "Block TOR" and "Block anonymisers" are reported at distance 0,
    because the application list of the first is a subset of the second – the first
    rule is redundant. At distance 1 the three regional DNS rules cluster together,
    since they differ in "locations" only, and "Allow NTP - Global" joins them: it
    has no location scope, so every location-scoped rule is a subset of it.
"""
import _bootstrap  # noqa: F401  pylint: disable=W0611  (puts ./src on sys.path)

from optimiser import FirewallOptimiser

from sample_data import FIREWALL_RULES

# Distances are explored from 0 up to, but excluding, the threshold
THRESHOLD = 2


def main() -> None:
    """ Build the optimiser, compute clusters and print them. """
    # Default and predefined rules are dropped by the optimiser: they cannot be edited
    optimiser = FirewallOptimiser(FIREWALL_RULES)

    print(f"Rules considered: {len(optimiser.rules)} of {len(FIREWALL_RULES)} exported")
    for rule in optimiser.rules:
        print(f"  [{rule.order}] {rule.name}")

    dsets = optimiser.get_dsets(THRESHOLD)

    # get_dsets() returns a list indexed by distance; each entry is a list of clusters,
    # and each cluster is a set of rule objects.
    for distance, clusters in enumerate(dsets):
        print(f"\nDistance {distance}: {len(clusters)} cluster(s)")

        for number, cluster in enumerate(clusters, start=1):
            print(f"  Cluster {number}:")
            for order, name in sorted((r.order, r.name) for r in cluster):
                print(f"    [{order}] {name}")


if __name__ == "__main__":
    main()
