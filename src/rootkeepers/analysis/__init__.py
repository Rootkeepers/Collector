"""Optional, failure-isolated security analysis for the TrustGate dashboard.

The authoritative install decision remains in ``interceptor/detailed_rule_engine``.
Everything in this package is advisory and must be safe to lose or disable.
"""

from .graph import run_ai_analysis
from .monitoring import monitor_project

__all__ = ["run_ai_analysis", "monitor_project"]
