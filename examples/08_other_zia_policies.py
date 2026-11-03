# pylint: disable=E0401, C0413
"""
    Example 8 – the remaining ZIA policy types.

    Run it with:  python examples/08_other_zia_policies.py

    SSL Inspection, File Type Control and Sandbox work exactly like the Firewall and
    URL optimisers of the earlier examples - same constructor, same get_dsets(), same
    exports. Only the input differs, and these three APIs are not published, so the
    dictionaries in sample_data.py were reverse-engineered from the UI.

    The one shape worth pointing out is the SSL rule: its action is a nested object,
    and the sub-actions the distance is computed over sit under a key named after the
    action type ("doNotDecryptSubActions" or "decryptSubActions"). A rule whose type
    is BLOCK has neither, and all of those criteria then read as False.

    The threshold is 3 here rather than the 2 used elsewhere, because the two Sandbox
    quarantine rules - which differ in file types only - are reported at distance 2
    instead of 1 in subset mode. See the note in README.md.
"""
import _bootstrap  # noqa: F401  pylint: disable=W0611  (puts ./src on sys.path)

from optimiser.optimisers.filetype_optimiser import FileTypeOptimiser
from optimiser.optimisers.sandbox_optimiser import SandboxOptimiser
from optimiser.optimisers.ssl_optimiser import SSLOptimiser

from reporting import print_clusters
from sample_data import FILETYPE_RULES, SANDBOX_RULES, SSL_RULES

THRESHOLD = 3


def main() -> None:
    """ Run the three remaining optimisers over their sample policies. """
    policies = (
        ("SSL Inspection", SSLOptimiser(SSL_RULES)),
        ("File Type Control", FileTypeOptimiser(FILETYPE_RULES)),
        ("Sandbox", SandboxOptimiser(SANDBOX_RULES)),
    )

    for title, optimiser in policies:
        print_clusters(optimiser.get_dsets(THRESHOLD), f"{title} clusters")

    # The SSL action is flattened onto the rule object, so sub-actions are plain
    # attributes by the time the distance is computed.
    print("\nFlattened SSL actions:")
    for rule in policies[0][1].rules:
        print(f"  [{rule.order}] {rule.name}: action={rule.action}, "
              f"ocsp_check={rule.oscp_check}, block_undecrypt={rule.block_undecrypt}")


if __name__ == "__main__":
    main()
