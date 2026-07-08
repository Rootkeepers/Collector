"""
Track A — npm 수집기 실행 진입점

사용법:
    python main.py [패키지명]

패키지명을 생략하면 기본값(lodash)으로 테스트 실행합니다.
"""
import sys

try:
    from .crawler import (
        fetch_package_data,
        collect_package_metadata,
        collect_artifact_info,
        collect_attestation_status,
        save_schema_mapping,
    )
except ImportError:  # pragma: no cover - supports direct execution from this folder
    from crawler import (
        fetch_package_data,
        collect_package_metadata,
        collect_artifact_info,
        collect_attestation_status,
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

    return save_schema_mapping(
        package_name,
        selected_version,
        metadata,
        artifact,
        attestation_status,
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


if __name__ == "__main__":
    target_package = sys.argv[1] if len(sys.argv) > 1 else "lodash"
    target_version = sys.argv[2] if len(sys.argv) > 2 else None
    run(target_package, target_version)
