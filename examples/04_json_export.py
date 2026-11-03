# pylint: disable=E0401, C0413
"""
    Example 4 – export clusters of ZIA URL Filtering rules as JSON.

    Run it with:  python examples/04_json_export.py

    dsets_to_dict() serialises whatever the last get_dsets() call produced, so it has
    to be called after it. The structure is:

        {"clusters": [{"distance": 0, "cluster_list": [[rule, rule], ...]}, ...]}

    where every rule is the attribute dictionary of the rule object. Those attributes
    hold Python sets, which json.dumps() cannot encode - hence the default= hook below.
"""
import json

import _bootstrap  # noqa: F401  pylint: disable=W0611  (puts ./src on sys.path)

from optimiser.optimisers.url_optimiser import URLOptimiser

from sample_data import URL_RULES

THRESHOLD = 2


def json_safe(value):
    """
        Encode the values json.dumps() does not handle natively.

        :param value: object the encoder could not serialise

        :return JSON-encodable replacement
    """
    if isinstance(value, set):
        return sorted(value)
    raise TypeError(f"Cannot serialise {type(value).__name__}")


def main() -> None:
    """ Cluster the URL rules and print the JSON representation. """
    optimiser = URLOptimiser(URL_RULES)
    optimiser.get_dsets(THRESHOLD)

    document = optimiser.dsets_to_dict()

    # Summarise first - the full dump is verbose, every rule carries ~35 attributes
    for entry in document["clusters"]:
        sizes = [len(cluster) for cluster in entry["cluster_list"]]
        print(f"distance {entry['distance']}: {len(sizes)} cluster(s), sizes {sizes}")

    print("\nNames only:")
    for entry in document["clusters"]:
        for cluster in entry["cluster_list"]:
            names = sorted(rule["name"] for rule in cluster)
            print(f"  distance {entry['distance']}: {names}")

    print("\nFirst rule of the first cluster, in full:")
    first = document["clusters"][-1]["cluster_list"][0][0]
    print(json.dumps(first, indent=2, default=json_safe, sort_keys=True))


if __name__ == "__main__":
    main()
