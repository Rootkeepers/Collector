import json
import requests

# 우리가 만든 두 개의 파서를 모두 불러옵니다!
from bundle_parser import BundleParseError, extract_predicate_from_dsse
from predicate_parser import parse_slsa_predicate

ATTESTATIONS_URL = "https://registry.npmjs.org/-/npm/v1/attestations/vite@5.2.0"

def fetch_and_test() -> None:
    print("[*] npm 레지스트리에서 vite@5.2.0의 전체 증명서를 가져옵니다...")
    try:
        response = requests.get(ATTESTATIONS_URL, timeout=15)
        response.raise_for_status()
        data = response.json()
    except Exception as error:
        print(f"[-] 데이터를 가져오는데 실패했습니다: {error}")
        return

    attestations = data.get("attestations", [])
    if not attestations:
        print("[-] 증명서(attestations) 배열을 찾을 수 없습니다.")
        return

    print(f"[*] 총 {len(attestations)}개의 증명서 봉투를 발견했습니다.\n")

    for index, attestation in enumerate(attestations, start=1):
        bundle = attestation.get("bundle", {})
        try:
            # [1단계] 번들 파서: DSSE 봉투를 해체하고 Predicate(알맹이) 추출
            predicate = extract_predicate_from_dsse(bundle)
        except BundleParseError:
            # 파싱할 수 없는 단순 영수증 등은 조용히 넘어갑니다.
            continue 

        # 진짜 SLSA 출처 증명서(빌드 족보)인지 확인
        if "buildDefinition" in predicate:
            print(f"=== [ 📦 봉투 {index}번: 진짜 SLSA 출처 증명서 해체 성공! ] ===")
            
            # [2단계] Predicate 파서: 거대한 족보에서 핵심 정보 3가지만 정규화하여 추출
            print("[*] Predicate 파서로 핵심 정보(저장소, 커밋, 워크플로)를 필터링합니다...\n")
            core_info = parse_slsa_predicate(predicate)
            
            print("✨ [ 최종 추출 결과 ] ✨")
            print(json.dumps(core_info, indent=2, ensure_ascii=False))
            print("\n🎉 축하합니다! 두 파서가 완벽하게 연결되어 동작합니다!")
            return

    print("[-] 진짜 SLSA 출처 증명서를 찾지 못했습니다.")

if __name__ == "__main__":
    fetch_and_test()