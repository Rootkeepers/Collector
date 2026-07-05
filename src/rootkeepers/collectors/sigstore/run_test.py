import json
import requests

from bundle_parser import BundleParseError, extract_predicate_from_dsse
from predicate_parser import parse_slsa_predicate
from oidc_parser import parse_fulcio_oidc_info, OIDCParseError
from rekor_parser import parse_rekor_log_info, RekorParseError
from cross_validator import validate_oidc_matches_predicate

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
        print("[-] 증명서 배열을 찾을 수 없습니다.")
        return

    for index, attestation in enumerate(attestations, start=1):
        bundle = attestation.get("bundle", {})
        try:
            predicate = extract_predicate_from_dsse(bundle)
        except BundleParseError:
            continue 

        if "buildDefinition" in predicate:
            print(f"\n=== [ 📦 봉투 {index}번: SLSA 출처 증명서 발견! ] ===")
            
            # 1. 내용물(Predicate) 파싱
            core_info = parse_slsa_predicate(predicate)
            
            # 2. 도장(OIDC & Rekor) 파싱
            verification_material = bundle.get("verificationMaterial", {})
            try:
                oidc_info = parse_fulcio_oidc_info(verification_material)
                rekor_info = parse_rekor_log_info(verification_material)
            except (OIDCParseError, RekorParseError) as e:
                print(f"[-] 인증서/로그 파싱 실패: {e}")
                continue

            print("[+] OIDC 정보 및 Rekor 로그 추출 성공!")
            
            # 3. 대망의 교차 검증 (Rule 5.4: OIDC Mismatch)
            print("[*] 교차 검증을 시작합니다...")
            validation_result = validate_oidc_matches_predicate(core_info, oidc_info)
            
            print("\n✨ [ 최종 교차 검증 결과 ] ✨")
            print(json.dumps(validation_result, indent=2, ensure_ascii=False))
            
            if validation_result["passed"]:
                print("\n🎉 [PASS] 서명된 OIDC 신원과 빌드 족보가 완벽하게 일치합니다!")
            else:
                print("\n🚨 [FAIL] OIDC Mismatch 감지! 위조된 서명일 가능성이 있습니다.")
            return

    print("[-] 진짜 SLSA 출처 증명서를 찾지 못했습니다.")

if __name__ == "__main__":
    fetch_and_test()