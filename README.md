# Track C 개발 일지: Sigstore/Rekor Provenance Collector

## 개발 목표

이 작업의 목표 : **Track C - Sigstore/Rekor Collector** 모듈을 구현하는 것.

이 모듈은 npm 패키지에 포함된 Sigstore attestation 정보를 분석하여, 패키지가 실제로 어떤 GitHub 저장소와 GitHub Actions 워크플로우에서 빌드되었는지를 추적. 최종적으로는 SLSA Provenance와 GitHub Actions OIDC 정보를 추출해, 패키지의 출처와 빌드 계보를 교차 검증하는 기반을 만드는 것이 핵심.

---

## Step 1: Bundle Parser 구현

먼저 `bundle_parser.py` 모듈을 구현.

Sigstore DSSE, 즉 **Dead Simple Signing Envelope** 형식의 attestation bundle을 해체하고, 내부에 Base64로 인코딩된 in-toto Statement를 복원한 뒤 SLSA `predicate` payload를 추출.

주요 구현 내용은 다음과 같다.

- `dsseEnvelope`가 포함된 Sigstore bundle과 raw DSSE envelope을 모두 처리
- envelope 내부의 `payload` 값을 안전하게 Base64 디코딩
- 디코딩된 UTF-8 JSON 문자열을 Python dictionary로 파싱
- SLSA `predicate`가 존재하면 해당 객체를 반환
- `predicate`가 없으면 디코딩된 statement 전체를 반환
- 손상된 bundle, 잘못된 Base64, JSON 파싱 실패 등에 대비해 `BundleParseError` 커스텀 예외 사용

`KeyError`, `TypeError`, `binascii.Error`, `UnicodeDecodeError`, `json.JSONDecodeError` 등을 명시적으로 처리, corrupted attestation이나 예기치 않은 구조가 들어와도 프로그램이 비정상 종료되지 않도록 했다.

---

## Step 2: 트러블슈팅 - npm API의 함정

초기 테스트에서는 `test_bundle.json` 파일을 사용해 parser를 검증했다. 그러나 테스트 결과 기대했던 GitHub Actions OIDC 정보나 SLSA 빌드 계보가 나오지 않는 문제가 있었다.

원인은 npm attestation API의 응답 구조.

npm API는 단일 attestation만 반환하는 것이 아니라, `"attestations"` 배열 안에 여러 개의 attestation을 반환. 이 배열에는 실제 SLSA Provenance뿐 아니라, 단순한 **Publish Attestation**도 포함.

초기 로직은 첫 번째 attestation만 파싱하고 있었고, 그 결과 실제 빌드 provenance가 아니라 다음과 같은 제한적인 publish receipt만 읽고 있었다.

- publish 관련 기본 정보
- public key 기반 정보
- GitHub Actions OIDC 및 빌드 lineage 없음

즉, parser가 실패한 것이 아니라 잘못된 attestation을 보고 있었던 것이다.

이를 해결하기 위해 `run_test.py`를 개선했다.

개선된 테스트 로직은 다음과 같다.

1. npm attestation API를 실시간으로 호출  
   `https://registry.npmjs.org/-/npm/v1/attestations/vite@5.2.0`

2. 응답 JSON에서 `"attestations"` 배열을 추출

3. 배열 내 모든 attestation을 순회하며 각 `bundle`을 `extract_predicate_from_dsse()`로 파싱

4. 추출된 predicate에 `"buildDefinition"` 키가 있는지 확인

5. `"buildDefinition"`이 없는 항목은 단순 publish receipt로 판단하고 제외

6. 실제 SLSA Provenance를 발견하면 성공 메시지와 함께 predicate 일부를 출력

이 방식으로 `vite@5.2.0` 패키지에서 실제 GitHub 빌드 계보를 포함한 SLSA Provenance를 성공적으로 분리.

---

## 현재까지의 성과

현재까지 구현된 핵심 성과는 다음과 같다.

- Sigstore DSSE envelope 해체 가능
- Base64 payload 복원 및 JSON 파싱 가능
- SLSA `predicate` 추출 가능
- 손상되거나 불완전한 bundle에 대한 안전한 예외 처리 구현
- npm API의 다중 attestation 구조 대응
- Publish Attestation과 SLSA Provenance 구분 가능
- `vite@5.2.0`을 대상으로 실제 SLSA Provenance 추출 검증 완료

---

## Step 3: Predicate Parser 구현 중

현재는 다음 단계인 `predicate_parser.py` 모듈을 구현 중이다.

SLSA predicate JSON에서 공급망 검증에 필요한 핵심 필드만 정규화해서 추출하는 것.

우선적으로 추출할 3가지 핵심 요소는 다음과 같다.

- `repository`: 빌드가 발생한 GitHub 저장소
- `commit`: 실제 빌드 대상이 된 Git commit SHA
- `workflow_path`: 실행된 GitHub Actions workflow 파일 경로

이 세 값은 이후 Track C의 핵심 검증 로직에서 사용될 예정. 예를 들어 npm 패키지의 provenance가 실제 GitHub 저장소의 특정 commit과 workflow에서 생성되었는지 확인, Rekor transparency log 및 GitHub OIDC claim과 교차 검증하는 기반 데이터.

---

## 다음 단계

다음 개발 단계는 다음과 같다.

1. `predicate_parser.py` 완성  
   SLSA predicate에서 repository, commit, workflow path를 안정적으로 추출한다.

2. 다양한 npm 패키지로 테스트 확대  
   `vite@5.2.0` 외에도 provenance가 존재하는 여러 패키지를 대상으로 구조 차이를 확인한다.

3. Rekor log 연동 준비  
   Sigstore bundle의 transparency log entry 및 certificate chain 정보를 분석할 수 있도록 확장한다.

4. GitHub Actions OIDC claim 교차 검증  
   SLSA provenance에 포함된 빌드 정보와 OIDC issuer/subject 정보를 비교해 신뢰성을 검증한다.

5. 최종 Collector 파이프라인 구성  
   npm 패키지명과 버전을 입력하면 provenance 수집, DSSE 파싱, predicate 정규화, 검증 결과 출력까지 이어지는 흐름을 만든다.

---

## 정리

이번 세션에서는 Sigstore/Rekor Collector의 가장 낮은 레벨인 **DSSE bundle parsing**과 **npm attestation 구조 분석**을 완료했다.

단순히 JSON을 읽는 수준이 아니라, 실제 npm API가 반환하는 다중 attestation 구조를 이해하고, 그 안에서 보안적으로 의미 있는 SLSA Provenance만 식별하는 로직을 마련했다는 점.
