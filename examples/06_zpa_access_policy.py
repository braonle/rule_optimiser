# pylint: disable=E0401, C0413
"""
    Example 6 – cluster ZPA Access Policy rules.

    Run it with:  python examples/06_zpa_access_policy.py

    ZPA rules do not carry their match criteria as named fields. Everything sits in a
    list of "conditions", each holding "operands" tagged with an objectType, and
    AccessRule sorts those operands into the attributes the distance is computed over.

    Two consequences are worth seeing in the output below:

    * SCIM, SAML and posture operands are keyed by their own name, so they become
      dynamic attributes ("SCIM department", "Posture AND", ...) that only exist for
      the policies that use them;
    * an unknown objectType raises ValueError rather than being ignored, so a rule
      type this library has not seen yet fails loudly instead of being mis-clustered.
"""
import _bootstrap  # noqa: F401  pylint: disable=W0611  (puts ./src on sys.path)

from optimiser.optimisers.access_optimiser import AccessPolicyOptimiser

from reporting import print_clusters
from sample_data import ACCESS_RULES

THRESHOLD = 2


def main() -> None:
    """ Cluster the ZPA rules and show the criteria that drive the distances. """
    optimiser = AccessPolicyOptimiser(ACCESS_RULES)

    print("Criteria parsed out of the conditions:\n")
    for rule in optimiser.rules:
        criteria = {key: sorted(value)
                    for key, value in rule.to_dict().items()
                    if isinstance(value, set) and value}
        print(f"  [{rule.order}] {rule.name}")
        for key, value in sorted(criteria.items()):
            print(f"        {key}: {value}")

    print_clusters(optimiser.get_dsets(THRESHOLD), "ZPA Access Policy clusters")

    # Rules 1 and 2 grant the same application group to different SCIM groups, so they
    # differ in one criterion. Rule 3 adds a client type on top of rule 1's audience.
    print("\nPair-wise distances:")
    for left in optimiser.rules:
        for right in optimiser.rules:
            if left.order < right.order:
                print(f"  {left.name!r} -> {right.name!r}: {left.distance_from(right)}")


if __name__ == "__main__":
    main()
