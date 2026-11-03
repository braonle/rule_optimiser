"""
    Make the examples runnable straight from a clone of the repository.

    When rule_optimiser is installed as a package (see README), this module is a
    no-op and can be dropped from the examples. It only exists so that

        python examples/01_firewall_clusters.py

    works without installing anything first, by prepending ./src to sys.path.
"""
import sys
from pathlib import Path

_SRC = Path(__file__).resolve().parents[1] / "src"

if _SRC.is_dir() and str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))
