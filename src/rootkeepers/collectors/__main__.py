"""Root CLI wrapper for the unified Rootkeepers lineage orchestrator."""

from __future__ import annotations

from rootkeepers.paths import load_env

load_env()

# FIXME: `rootkeepers.engine` 은 존재하지 않는다(리팩터링 때 사라진 경로로 보인다).
#        lineage 오케스트레이터의 CLI 진입점을 다시 붙여야 이 파일이 동작한다.
#        지금 쓸 수 있는 함수는 rootkeepers.interceptor.lineage 의
#        collect_release_lineage_report(package_name, version) 이다.
from rootkeepers.engine.lineage import main


if __name__ == "__main__":
    raise SystemExit(main())
