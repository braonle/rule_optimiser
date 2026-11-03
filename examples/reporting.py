# pylint: disable=E0401
"""
    Small console formatter shared by the examples.

    It is the same loop that 01_firewall_clusters.py spells out inline: the result
    of RuleOptimiser.get_dsets() is indexed by distance first, then by cluster.
"""
from optimiser.rules.policy_rule import PolicyRule


def print_clusters(dsets: list[list[set[PolicyRule]]], title: str = "Clusters") -> None:
    """
        Print clusters grouped by the distance they were found at.

        :param list[list[set[PolicyRule]]]  dsets: return value of get_dsets()
        :param str                          title: heading to print above the report
    """
    print(f"\n{title}")
    print("=" * len(title))

    for distance, clusters in enumerate(dsets):
        if not clusters:
            print(f"\nDistance {distance}: no clusters")
            continue

        print(f"\nDistance {distance}: {len(clusters)} cluster(s)")

        for number, cluster in enumerate(clusters, start=1):
            # Rules are held in a set, so sort by order to keep the output stable
            names = sorted((rule.order, rule.name) for rule in cluster)
            print(f"  Cluster {number}:")
            for order, name in names:
                print(f"    [{order}] {name}")
