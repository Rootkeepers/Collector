import json
import requests

# 1. 테스트할 패키지 지정
package_name = "eve"
url = f"https://registry.npmjs.org/{package_name}"
response = requests.get(url)

if response.status_code == 200:
    data = response.json()

    # 가장 최신(latest) 버전 데이터 조준
    latest_version = data.get("dist-tags", {}).get("latest")
    version_data = data.get("versions", {}).get(latest_version)

    # --------------------------------------------------------
    # [2번 기능] 거대한 데이터에서 핵심 메타데이터 파싱 (알맹이 추출)
    # --------------------------------------------------------
    published_at = data.get("time", {}).get(latest_version)  # 배포 시각
    dist = version_data.get("dist", {})
    integrity = dist.get("integrity")  # 무결성 SHA512 값
    git_head = version_data.get("gitHead")  # 깃허브 커밋 해시

    # 출처(Repository) 주소 추출
    repository_info = version_data.get("repository", {})
    repo_url = ""
    if isinstance(repository_info, dict):
        repo_url = repository_info.get("url", "")
    elif isinstance(repository_info, str):
        repo_url = repository_info

    # --------------------------------------------------------
    # [3번 기능] Track A 명세서 기반 "3대 결측치 필터링" 검사
    # --------------------------------------------------------
    decision = "PASS"
    reason = "정상 검증 완료"

    if not git_head:
        decision = "UNVERIFIABLE"
        reason = "결측 처리: gitHead 정보가 없음"
    elif not repo_url:
        decision = "UNVERIFIABLE"
        reason = "결측 처리: repository 정보가 없음"
    elif "github.com" not in repo_url.lower():
        decision = "UNVERIFIABLE"
        reason = "결측 처리: GitHub 저장소가 아님 (non-github)"

    # Attestation(증명서)이 없다면 RISK로 조정 (필터를 통과했을 때만)
    if decision == "PASS":
        has_real_attestation = "attestations" in dist
        if not has_real_attestation:
            decision = "RISK"
            reason = "보증서(Attestation)가 존재하지 않음"

    # --------------------------------------------------------
    # [공통 스키마 매핑] 팀 공통 양식 구조에 맞게 포장
    # --------------------------------------------------------
    schema_result = {
        "package": {
            "name": package_name,
            "version": latest_version,
            "published_at": published_at,
        },
        "artifact": {
            "source": "npm",
            "integrity": integrity,
            "git_head": git_head,
            "attestation": "PRESENT" if "attestations" in dist else "ABSENT",
        },
        "workflow": {},  # 다음 단계(GitHub API)에서 채울 칸들
        "commit": {},
        "result": {"decision": decision, "reason": reason},
    }

    # 최종 정제된 결과 파일 저장
    with open("schema_result.json", "w", encoding="utf-8") as f:
        json.dump(schema_result, f, indent=2, ensure_ascii=False)

    print("========================================")
    print(f"🎉 [검증 완료] 결과: {decision} ({reason})")
    print("💾 결과가 'schema_result.json' 파일로 저장되었습니다.")
    print("========================================")