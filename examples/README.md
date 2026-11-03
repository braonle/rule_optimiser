# Examples

Runnable examples for the rule optimiser. Each file is self-contained, prints its
result to the console and explains in its docstring what the output should look like
and why.

## Running them

The examples work straight from a clone:

```shell
python examples/01_firewall_clusters.py
```

`_bootstrap.py` prepends `./src` to `sys.path` to make that work. If the package is
installed (see the main [README](../README.md)), the import is a harmless no-op and
can be dropped from your own code.

## The examples

| File | What it shows |
| --- | --- |
| [01_firewall_clusters.py](01_firewall_clusters.py) | The basic flow: build an optimiser from exported rules, call `get_dsets()`, walk the result |
| [02_distance_distribution.py](02_distance_distribution.py) | Using `get_distance_distribution()` to pick a threshold instead of guessing one |
| [03_subsets_vs_exact.py](03_subsets_vs_exact.py) | What `search_subsets` changes, and why containment is what exposes redundant rules |
| [04_json_export.py](04_json_export.py) | `dsets_to_dict()`, the shape of the document and how to JSON-encode it |
| [05_excel_export.py](05_excel_export.py) | `dsets_to_excel()`, one worksheet per distance, several policy types in one workbook |
| [06_zpa_access_policy.py](06_zpa_access_policy.py) | ZPA Access Policy: conditions and operands, and the dynamic SCIM/SAML/posture criteria |
| [07_custom_rule_type.py](07_custom_rule_type.py) | Supporting a policy type the library does not ship with, by subclassing `PolicyRule` and `RuleOptimiser` |
| [08_other_zia_policies.py](08_other_zia_policies.py) | SSL Inspection, File Type Control and Sandbox, including the nested SSL action object |

Two supporting modules are shared by the examples rather than being examples
themselves: [sample_data.py](sample_data.py) holds the policy exports and
[reporting.py](reporting.py) holds the console formatter.

## About the sample data

Every dictionary in `sample_data.py` has the shape of the corresponding API response
and is handed to the optimiser unmodified, which is how a real export is used. The
data is small and hand-crafted so that the reported clusters can be checked by eye.

Where the API is published, the docstring in `sample_data.py` links to it. The SSL
Inspection, File Type Control and Sandbox APIs are not published and their payloads
were reverse-engineered from the UI, so treat those three as a best-effort shape.

## Reading the output

`get_dsets(threshold)` returns a list indexed by distance, holding a list of clusters,
each of which is a `set` of rule objects:

```python
dsets = optimiser.get_dsets(2)
dsets[1][0]       # first cluster of rules that are at most distance 1 apart
```

Distances are explored from `0` up to but **excluding** the threshold, so
`get_dsets(2)` reports distances 0 and 1. A cluster is only listed at the lowest
distance it appears at, degenerate single-rule clusters are dropped, and one rule can
appear in several clusters - that last point is deliberate and is what makes the
output a review list rather than a partition.