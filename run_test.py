import json
import requests
from sigstore_collector import parse_sigstore_bundle

def fetch_and_test():
    # 1. 테스트용 패키지 설정 (sigstore의 최신 버전 중 하나)
    package_name = "sigstore"
    package_version = "5.0.0"  # <-- 이 부분을 5.0.0으로 변경!
    url = f"https://registry.npmjs.org/-/npm/v1/attestations/{package_name}@{package_version}"

    print(f"[*] npm 레지스트리에서 {package_name}@{package_version}의 증명서를 가져옵니다...")
    response = requests.get(url)
    
    if response.status_code != 200:
        print("[-] 증명서를 가져오는데 실패했습니다.")
        return

    data = response.json()
    
    # 2. npm API 응답에서 실제 Sigstore bundle 부분만 추출
    try:
        bundle = data["attestations"][0]["bundle"]
    except (KeyError, IndexError):
        print("[-] 패키지에 Sigstore 번들이 포함되어 있지 않습니다.")
        return

    # 3. 로컬 파일로 임시 저장 (파서가 파일 경로를 요구하므로)
    test_filepath = "test_bundle.json"
    with open(test_filepath, "w", encoding="utf-8") as f:
        json.dump(bundle, f, indent=2)
    print(f"[*] 임시 번들 파일 저장 완료: {test_filepath}")

    # 4. 작성하신 수집기 모듈 실행
    print("\n[*] 파싱을 시작합니다...\n")
    result = parse_sigstore_bundle(test_filepath)

    # 5. 결과 출력
    print("=== [ 파싱 결과 (TrustGate JSON) ] ===")
    print(json.dumps(result, indent=2, ensure_ascii=False))

if __name__ == "__main__":
    fetch_and_test()