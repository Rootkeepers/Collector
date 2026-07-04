"""
Track A — npm 수집기 실행 진입점

사용법:
    python main.py [패키지명]

패키지명을 생략하면 기본값(lodash)으로 테스트 실행합니다.
"""
import sys

from crawler import (
    fetch_package_data,
    collect_package_metadata,
    collect_artifact_info,
    collect_attestation_status,
    save_schema_mapping,
)


def run(package_name: str) -> dict | None:
    """지정한 패키지에 대해 전체 수집 파이프라인을 실행합니다."""
    raw_data = fetch_package_data(package_name)
    if raw_data is None:
        return None

    latest_version = raw_data.get("dist-tags", {}).get("latest")
    version_data = raw_data.get("versions", {}).get(latest_version)

    if not latest_version or not version_data:
        print("패키지의 버전 정보를 찾을 수 없습니다.")
        return None

    # 1. 패키지 메타데이터 수집
    metadata = collect_package_metadata(raw_data, latest_version)

    # 2. 아티팩트 정보 수집
    artifact = collect_artifact_info(version_data)

    # 3. Attestation 존재 여부 수집
    attestation_status = collect_attestation_status(version_data)

    # 4. 최종 스키마 매핑 및 저장
    result = save_schema_mapping(
        package_name, latest_version, metadata, artifact, attestation_status
    )

    print("========================================")
    print("[수집 완료] npm 패키지 메타데이터 정제 성공")
    print("결과가 'schema_result.json' 파일로 저장되었습니다.")
    print("========================================")

    return result


if __name__ == "__main__":
    target_package = sys.argv[1] if len(sys.argv) > 1 else "lodash"
    run(target_package)