import json
import requests

def collect_package_metadata(data, latest_version):
    """
    [1] 패키지 메타데이터 수집
    패키지명, 버전, 배포 시각(published_at)을 수집합니다.
    """
    published_at = data.get("time", {}).get(latest_version)
    return {
        "published_at": published_at
    }

def collect_artifact_info(version_data):
    """
    [2] 아티팩트 정보 수집
    integrity, gitHead, repository 정보를 추출합니다.
    """
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

    return {
        "integrity": integrity,
        "git_head": git_head,
        "repo_url": repo_url
    }

def collect_attestation_status(version_data):
    """
    [3] Attestation 수집 및 검사
    Provenance Attestation의 존재 여부를 파악합니다.
    """
    dist = version_data.get("dist", {})
    has_attestation = "attestations" in dist
    return "PRESENT" if has_attestation else "ABSENT"

def save_schema_mapping(package_name, latest_version, metadata, artifact, attestation_status):
    """
    [4] 공통 스키마 매핑 및 저장
    팀 공통 양식 구조에 맞게 데이터를 포장하고 JSON 파일로 저장합니다.
    """
    schema_result = {
        "package": {
            "name": package_name,
            "version": latest_version,
            "published_at": metadata.get("published_at"),
        },
        "artifact": {
            "source": "npm",
            "integrity": artifact.get("integrity"),
            "git_head": artifact.get("git_head"),
            "repo_url": artifact.get("repo_url"),  # 추후 Track B 연동을 위해 저장
            "attestation": attestation_status,
        },
        "workflow": {},  # Track B(GitHub 수집기)에서 채울 칸
        "commit": {},    # Track B에서 채울 칸
        "result": {},    # 판정 로직 제외로 빈 칸 유지
    }

    # 최종 정제된 결과 파일 저장
    output_filename = "schema_result.json"
    with open(output_filename, "w", encoding="utf-8") as f:
        json.dump(schema_result, f, indent=2, ensure_ascii=False)
        
    print("========================================")
    print(f"[수집 완료] npm 패키지 메타데이터 정제 성공")
    print(f"결과가 '{output_filename}' 파일로 저장되었습니다.")
    print("========================================")
    
    return schema_result

# --------------------------------------------------------
# 메인 실행 흐름
# --------------------------------------------------------
if __name__ == "__main__":
    # 테스트할 패키지 지정
    package_name = "lodash"
    url = f"https://registry.npmjs.org/{package_name}"
    response = requests.get(url)

    if response.status_code == 200:
        raw_data = response.json()

        # 가장 최신(latest) 버전 데이터 조준
        latest_version = raw_data.get("dist-tags", {}).get("latest")
        version_data = raw_data.get("versions", {}).get(latest_version)

        if latest_version and version_data:
            # 1. 패키지 메타데이터 수집
            metadata = collect_package_metadata(raw_data, latest_version)
            
            # 2. 아티팩트 정보 수집
            artifact = collect_artifact_info(version_data)
            
            # 3. Attestation 존재 여부 수집
            attestation_status = collect_attestation_status(version_data)
            
            # 4. 최종 스키마 매핑 및 저장 
            save_schema_mapping(package_name, latest_version, metadata, artifact, attestation_status)
        else:
            print("패키지의 버전 정보를 찾을 수 없습니다.")
    else:
        print(f"npm 레지스트리 요청 실패 (Status Code: {response.status_code})")