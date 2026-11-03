# Rule Optimiser

Find clusters of *similar enough* ZIA and ZPA policy rules, so that candidates for a
manual merge can be reviewed instead of hunted for by hand.

> **Disclaimer** – this repository is **not official**. It is not a product of, and is
> not endorsed, certified or supported by, any vendor. It is provided **as is**, with
> no warranties or guarantees of any kind. **Use at your own risk.** See
> [Disclaimer](#disclaimer) for the full text.

A rule is treated as a vector of match criteria, with this metric:

1. The distance between rule A and rule B is the number of match criteria that differ
   between them.
2. If a match criterion in A is a subset of the corresponding criterion in B, it does
   not contribute to the distance.

Rule 2 can be turned off with the *search_subsets* argument of the **RuleOptimiser**
child classes, which falls back to requiring the criteria to be equal.

**Distance 0** means the rules are effectively identical, or that one rule in the
cluster fully includes the rest.

**Cluster** – a set of rules that do not differ from each other by more than a
predefined distance.

## Algorithm

Although the task looks like ordinary clustering, it has two significant distinctions:

1. One rule can be present in several clusters;
2. Only the largest clusters are needed: (A,B,C) is enough, and (A,B) would have been
   a wrong answer.

The idea is somewhat similar to greedy breadth-first search. First the target sets are
defined as single-element sets, then other rules are added to them.

1. Initialise sets from rules: `[A, B, C, ...]` → `[(A), (B), (C), ...]`
2. Iterate over rules and try adding them to the sets while adhering to the distance
   threshold: `A + [(A), (B), (C), ...] = [(A), (AB), (AC), ...]`
3. Remove all duplicates to reduce processing:
   `B + [(A), (AB), (AC), ...] = [(AB), (AB), (ABC), ...]` → `[(AB), (ABC), ...]`
4. Note that eventually the subsets become equal to the supersets and are removed as
   well: `C + [(AB), (ABC), ...] = [(ABC), (ABC), ...]` → `[(ABC), ...]`

# Usage

This project is the backend library with the object and logic implementation. If you
are looking to *use* the optimiser rather than contribute to it, a separate CLI
counterpart provides a proper interface along with its own documentation.

## Supported policy types

Each optimiser takes the API response for its policy, decoded from JSON and otherwise
unmodified. Rules that cannot be edited are skipped where the payload identifies them.

| Policy | Class | Import from | Worksheet prefix | 
| --- | --- | --- |-------------------|
| ZIA Firewall Control | `FirewallOptimiser` | `optimiser` | `FW distance {n}` |
| ZIA URL Filtering | `URLOptimiser` | `optimiser.optimisers.url_optimiser` | `URL distance {n}` |
| ZIA SSL Inspection | `SSLOptimiser` | `optimiser.optimisers.ssl_optimiser` | `SSL distance {n}` |
| ZIA File Type Control | `FileTypeOptimiser` | `optimiser.optimisers.filetype_optimiser` | `File distance {n}` |
| ZIA Sandbox | `SandboxOptimiser` | `optimiser.optimisers.sandbox_optimiser` | `Sandbox distance {n}` |
| ZPA Access Policy | `AccessPolicyOptimiser` | `optimiser.optimisers.access_optimiser` | `Access Rule distance {n}` |

Only the Firewall, URL Filtering and ZPA Access Policy APIs are published:

* [Firewall Control](https://help.zscaler.com/zia/firewall-policies#/firewallFilteringRules-get)
* [URL Filtering](https://help.zscaler.com/zia/url-filtering-policies#/urlFilteringRules-get)
* [ZPA Access Policy](https://help.zscaler.com/zpa/configuring-access-policies-using-api)

The SSL Inspection, File Type Control and Sandbox payloads were reverse-engineered
from the UI, as well as some fields missing from the published documentation.

## Quick start

```python
import json

from optimiser import FirewallOptimiser

with open("firewall_rules.json", encoding="utf-8") as handle:
    rules = json.load(handle)

optimiser = FirewallOptimiser(rules)                # search_subsets=True by default

# Pick a threshold from the pair-wise distance histogram instead of guessing
distribution = optimiser.get_distance_distribution()
threshold = max(distribution, key=distribution.get) + 1

# Distances are explored from 0 up to, but excluding, the threshold
dsets = optimiser.get_dsets(threshold)

for distance, clusters in enumerate(dsets):
    for cluster in clusters:
        print(f"distance {distance}: {sorted(rule.name for rule in cluster)}")

optimiser.dsets_to_excel("clusters.xlsx")           # one worksheet per distance
```

`get_dsets()` returns a list indexed by distance, holding a list of clusters, each of
which is a `set` of rule objects:

```python
dsets[1][0]     # first cluster of rules that are at most distance 1 apart
```

A cluster is only listed at the lowest distance it appears at, single-rule clusters are
dropped, and one rule can appear in several clusters – that last point is deliberate,
and is what makes the output a review list rather than a partition.

## Examples

Runnable, self-contained examples live in [examples/](examples/) and work straight from
a clone:

```shell
python examples/01_firewall_clusters.py
```

They cover the basic flow, choosing a threshold, `search_subsets`, the JSON and Excel
exports, ZPA conditions and operands, the three unpublished ZIA policy types, and how
to support a policy type the library does not ship with. See
[examples/README.md](examples/README.md) for the full list.

# API

## RuleOptimiser

Base class; the child classes listed above implement initialisation only.

| Member | Description |
| --- | --- |
| `rules` | Tuple of rule objects, after the uneditable rules have been dropped |
| `dsets` | Result of the last `get_dsets()` call; the exports read it |
| `get_dsets(threshold)` | Compute clusters for distances `0 .. threshold - 1` |
| `get_distance_distribution()` | `{distance: number of pairs}` over every pair of rules |
| `dsets_to_dict()` | `{"clusters": [{"distance": int, "cluster_list": [[rule, ...]]}]}` |
| `dsets_to_excel(filename, folder=".")` | Write one worksheet per distance |

`dsets_to_dict()` and `dsets_to_excel()` serialise whatever the last `get_dsets()` call
produced, so they have to be called after it.

`dsets_to_excel()` opens an existing workbook and adds to it rather than overwriting,
so several policy types can share one file. It strips path separators out of both
arguments, so `folder` must be a plain directory name rather than a nested path.
Columns are taken from the attributes of the rule class, skipping callables and names
starting with `_`.

## PolicyRule

Abstract base class for a single rule. A subclass has to provide `__init__` (turn one
API dictionary into attributes), `distance_from()` (count the criteria that do not
match) and `_key()` (a tuple identifying the rule, used for hashing and equality).

| Member | Description |
| --- | --- |
| `distance_from(other)` | Abstract; distance to another rule |
| `distance_to_set(st, max_dist, distance_mapper)` | Distance to a set, as the max of the pair-wise distances |
| `distance_within_set(st, max_dist, distance_mapper)` | Static; max distance between any two rules of a set |
| `to_dict()` | Attribute dictionary, used by both exports |

Class-level attribute declarations are not decoration: `dsets_to_excel()` reads them off
the rule class to work out the columns.

Each rule type ships in two variants – for example `FirewallRule` and
`FirewallRuleWithSubsets` – which the optimiser picks between based on
`search_subsets`. Note that an empty criterion means "any", and is therefore treated as
the widest possible superset.

## Extending

Supporting a new policy type means subclassing `PolicyRule` and `RuleOptimiser`; none
of the clustering logic has to be touched. The optimiser only has to populate
`self.rules` and declare `_rule_cls` (the class whose attributes become the Excel
columns) and `_worksheet_fmt_name` (the worksheet title, with an `{n}` placeholder for
the distance). [examples/07_custom_rule_type.py](examples/07_custom_rule_type.py) is a
worked example.

# Disclaimer

This repository is **not official**. It is not a product of, and is not endorsed,
certified or supported by, any vendor whose products or APIs it refers to. Product
names and documentation links are used for identification purposes only.

The software is provided **"as is"**, without warranty of any kind, express or implied,
including but not limited to the warranties of merchantability, fitness for a
particular purpose and non-infringement. **No guarantees are provided** that it is
correct, complete, secure or suitable for any purpose, and nobody is under any
obligation to provide support, fixes or updates for it.

**Use at your own risk.** In particular:

* the clusters it reports are a **review aid, not a recommendation** – every suggested
  merge has to be verified by a human before anything is changed;
* merging policy rules changes how traffic is enforced, and can break access or weaken
  your security posture if it is done without review;
* the library may contain defects, and several of the payload formats it parses are
  reverse-engineered, so they may differ from the real APIs or stop matching them;
* validate the output against the live policy, and test any resulting change in a
  non-production configuration before rolling it out.

In no event shall the authors or contributors be liable for any claim, damages or other
liability arising from, out of, or in connection with the software or its use.
