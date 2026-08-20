"""Track A — npm metadata collector command."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

try:
    from .crawler import (
        fetch_package_data,
        collect_package_metadata,
        collect_artifact_info,
        collect_attestation_status,
        collect_release_baseline,
        save_schema_mapping,
    )
except ImportError:  # pragma: no cover - supports direct execution from this folder
    from crawler import (
        fetch_package_data,
        collect_package_metadata,
        collect_artifact_info,
        collect_attestation_status,
        collect_release_baseline,
        save_schema_mapping,
    )


def collect_npm_release(
    package_name: str,
    version: str | None = None,
    *,
    output_filename: str | None = None,
) -> dict | None:
    """지정한 npm 패키지/버전의 메타데이터와 아티팩트 정보를 수집합니다."""
    raw_data = fetch_package_data(package_name)
    if raw_data is None:
        return None

    selected_version = version or raw_data.get("dist-tags", {}).get("latest")
    version_data = raw_data.get("versions", {}).get(selected_version)

    if not selected_version or not version_data:
        print("패키지의 버전 정보를 찾을 수 없습니다.")
        return None

    metadata = collect_package_metadata(raw_data, selected_version)
    artifact = collect_artifact_info(version_data)
    attestation_status = collect_attestation_status(version_data)
    baseline = collect_release_baseline(raw_data, selected_version)

    return save_schema_mapping(
        package_name,
        selected_version,
        metadata,
        artifact,
        attestation_status,
        baseline,
        output_filename=output_filename,
    )


def run(package_name: str, version: str | None = None) -> dict | None:
    """지정한 패키지에 대해 전체 수집 파이프라인을 실행합니다."""
    result = collect_npm_release(
        package_name,
        version,
        output_filename="schema_result.json",
    )
    if result is None:
        return None

    print("========================================")
    print("[수집 완료] npm 패키지 메타데이터 정제 성공")
    print("결과가 'schema_result.json' 파일로 저장되었습니다.")
    print("========================================")

    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m rootkeepers.collectors.npm",
        description="npm 릴리스 메타데이터와 공급망 기준선을 수집합니다.",
    )
    parser.add_argument("package", help="npm 패키지명, 예: lodash 또는 @scope/name")
    parser.add_argument("version", nargs="?", help="정확한 버전. 생략하면 latest")
    parser.add_argument(
        "-o", "--output", type=Path,
        help="JSON 파일 경로. 생략하면 표준 출력에만 표시합니다.",
    )
    args = parser.parse_args(argv)

    result = collect_npm_release(args.package, args.version, output_filename=None)
    if result is None:
        return 1
    rendered = json.dumps(result, indent=2, ensure_ascii=False)
    if args.output is None:
        print(rendered)
        return 0
    try:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
    except OSError as exc:
        print(f"결과 파일을 쓸 수 없습니다: {exc}", file=sys.stderr)
        return 1
    print(f"[수집 완료] {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
