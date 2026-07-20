"""Root CLI wrapper for the unified Rootkeepers lineage orchestrator."""

from __future__ import annotations

import sys
from pathlib import Path

from dotenv import load_dotenv


PROJECT_ROOT = Path(__file__).resolve().parent
load_dotenv(PROJECT_ROOT / ".env")

SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from rootkeepers.engine.lineage import main


if __name__ == "__main__":
    raise SystemExit(main())
