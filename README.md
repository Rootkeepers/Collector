# Track C 개발 일지: Sigstore/Rekor Provenance Collector

## 개발 목표

이 작업의 목표는 **Track C - Sigstore/Rekor Collector** 모듈을 구현하는 것이다.

이 모듈은 npm 패키지에 포함된 Sigstore attestation 정보를 분석하여, 패키지가 실제로 어떤 GitHub 저장소와 GitHub Actions 워크플로우에서 빌드되었는지를 추적한다. 최종적으로는 SLSA Provenance, Fulcio OIDC 인증서, Rekor transparency log를 함께 분석해 npm 패키지의 출처와 빌드 계보를 교차 검증하는 것이 핵심이다.

Track C는 단순히 attestation JSON을 읽는 수집기가 아니라, **서명 주체가 주장하는 신원**, **SLSA predicate가 주장하는 빌드 정보**, **Rekor에 기록된 투명성 로그**를 연결해 공급망 보안 관점의 신뢰 판단 근거를 제공하는 역할을 한다.

---

## Step 1: Bundle Parser 구현

먼저 `bundle_parser.py` 모듈을 구현했다.

Sigstore DSSE, 즉 **Dead Simple Signing Envelope** 형식의 attestation bundle을 해체하고, 내부에 Base64로 인코딩된 in-toto Statement를 복원한 뒤 SLSA `predicate` payload를 추출한다.

주요 구현 내용은 다음과 같다.

- `dsseEnvelope`가 포함된 Sigstore bundle과 raw DSSE envelope을 모두 처리
- envelope 내부의 `payload` 값을 안전하게 Base64 디코딩
- 디코딩된 UTF-8 JSON 문자열을 Python dictionary로 파싱
- SLSA `predicate`가 존재하면 해당 객체를 반환
- `predicate`가 없으면 디코딩된 statement 전체를 반환
- 손상된 bundle, 잘못된 Base64, JSON 파싱 실패 등에 대비해 `BundleParseError` 커스텀 예외 사용

`KeyError`, `TypeError`, `binascii.Error`, `UnicodeDecodeError`, `json.JSONDecodeError` 등을 명시적으로 처리해 corrupted attestation이나 예기치 않은 구조가 들어와도 프로그램이 비정상 종료되지 않도록 했다.

---

## Step 2: 트러블슈팅 - npm API의 함정

초기 테스트에서는 `test_bundle.json` 파일을 사용해 parser를 검증했다. 그러나 테스트 결과 기대했던 GitHub Actions OIDC 정보나 SLSA 빌드 계보가 나오지 않는 문제가 있었다.

원인은 npm attestation API의 응답 구조였다.

npm API는 단일 attestation만 반환하는 것이 아니라, `"attestations"` 배열 안에 여러 개의 attestation을 반환한다. 이 배열에는 실제 SLSA Provenance뿐 아니라 단순한 **Publish Attestation**도 포함된다.

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

6. 실제 SLSA Provenance를 발견하면 후속 parser와 validator로 전달

이 방식으로 `vite@5.2.0` 패키지에서 실제 GitHub 빌드 계보를 포함한 SLSA Provenance를 성공적으로 분리했다.

---

## Step 3: Predicate Parser 구현 완료

다음 단계로 `predicate_parser.py` 모듈을 구현했다.

이 모듈의 책임은 거대한 SLSA predicate JSON에서 공급망 검증에 필요한 핵심 필드만 정규화해서 추출하는 것이다.

정규화해서 추출하는 3가지 핵심 요소는 다음과 같다.

- `repository`: 빌드가 발생한 GitHub 저장소
- `commit`: 실제 빌드 대상이 된 Git commit SHA
- `workflow_path`: 실행된 GitHub Actions workflow 파일 경로

`parse_slsa_predicate(predicate: dict) -> dict` 함수는 항상 `repository`, `commit`, `workflow_path` 세 개의 키를 가진 dictionary를 반환한다. SLSA v1.0 구조를 기준으로 `buildDefinition.externalParameters.workflow.repository`, `buildDefinition.externalParameters.source.repository`, `buildDefinition.externalParameters.workflow.path`, `buildDefinition.resolvedDependencies[].digest`를 안전하게 탐색한다.

SLSA predicate 구조는 패키지나 빌드 시스템에 따라 달라질 수 있으므로, 모든 중첩 필드 접근은 안전한 `.get()` 기반 탐색과 타입 확인을 사용했다. 필드가 누락되었거나 `null`이거나 예상과 다른 타입이어도 `KeyError`나 `TypeError`로 중단되지 않고, 찾을 수 없는 값은 빈 문자열 `""`로 정규화한다.

이 parser는 이후 Fulcio OIDC claim과 비교할 기준 데이터를 제공한다. 특히 `repository`와 `workflow_path`는 OIDC 교차 검증의 핵심 입력값이다.

---

## Step 4: Fulcio OIDC & Rekor Parser 구현

Track C의 핵심 신뢰 근거를 확보하기 위해 `oidc_parser.py`와 `rekor_parser.py`를 추가로 구현했다.

### Fulcio OIDC Parser

`oidc_parser.py`는 Sigstore bundle의 `verificationMaterial` 객체에서 Fulcio x509 certificate chain을 읽고, leaf certificate에 포함된 OIDC 신원 정보를 추출한다.

주요 구현 내용은 다음과 같다.

- `verificationMaterial.x509CertificateChain`에서 leaf certificate 추출
- PEM 형식과 Base64 DER 형태의 certificate 입력 처리
- `cryptography` 라이브러리를 사용한 x509 certificate 파싱
- Fulcio OIDC issuer extension 추출
- Subject Alternative Name 기반 OIDC subject 추출
- GitHub Actions 환경에서 사용되는 Fulcio custom OID extension 추출
- `subject_repo`, `subject_workflow` 등 교차 검증에 필요한 값 정규화
- malformed certificate, 누락된 chain, 잘못된 인코딩에 대비한 `OIDCParseError` 커스텀 예외 사용

이 parser를 통해 다음과 같은 정보를 얻을 수 있다.

- `issuer`: OIDC 토큰 발급자. 예: `https://token.actions.githubusercontent.com`
- `subject`: Fulcio certificate에 기록된 OIDC subject
- `subject_repo`: subject 또는 GitHub custom OID에서 추출한 저장소
- `subject_workflow`: subject 또는 signer URI에서 추출한 workflow path
- GitHub custom OID 기반 workflow, repository, ref, SHA, runner 환경 정보

### Rekor Transparency Log Parser

`rekor_parser.py`는 `verificationMaterial.tlogEntries` 배열에서 Rekor transparency log metadata를 추출한다.

주요 구현 내용은 다음과 같다.

- `tlogEntries` 배열 접근
- 첫 번째 Rekor log entry에서 `logIndex` 추출
- 첫 번째 Rekor log entry에서 `integratedTime` 추출
- 값이 문자열로 들어오는 Sigstore bundle 구조를 고려해 integer로 정규화
- `tlogEntries`가 비어 있으면 `None` 반환
- malformed log entry에 대비한 `RekorParseError` 커스텀 예외 사용

Rekor parser는 패키지 provenance가 transparency log에 기록되었는지 확인하기 위한 최소한의 감사 정보를 제공한다. `logIndex`는 Rekor 내 위치를, `integratedTime`은 로그에 통합된 시점을 나타낸다.

---

## Step 5: OIDC 교차 검증 (Cross-Validation) 엔진 구현 완료

마지막으로 `cross_validator.py`를 구현해 SLSA predicate와 Fulcio OIDC claim을 교차 검증하는 엔진을 완성했다.

이 validator의 목적은 서명에 사용된 OIDC 신원과 attestation payload가 주장하는 빌드 출처가 서로 일치하는지 확인하는 것이다. 특히 **Rule 5.4: OIDC Mismatch** 취약점을 탐지하는 데 초점을 둔다.

검증 입력은 다음과 같다.

- SLSA predicate 정보
  - `repository`
  - `workflow_path`

- Fulcio OIDC 정보
  - `subject_repo`
  - `subject_workflow`
  - `issuer`
  - `subject`

검증 로직은 다음과 같다.

1. SLSA predicate의 `repository`를 정규화
2. OIDC subject 또는 GitHub custom OID에서 추출한 `subject_repo`를 정규화
3. 두 repository 값이 일치하는지 비교
4. SLSA predicate의 `workflow_path`를 정규화
5. OIDC에서 추출한 `subject_workflow`를 정규화
6. 양쪽 workflow 정보가 모두 존재하는 경우 서로 일치하는지 비교
7. 불일치가 발견되면 `OIDC_MISMATCH` rule 위반으로 `FAIL` 반환

`cross_validator.py`는 단순 boolean뿐 아니라, 다음과 같은 구조화된 검증 결과를 반환한다.

- `status`: `PASS` 또는 `FAIL`
- `passed`: boolean 결과
- `rule`: 적용된 탐지 rule
- `predicate`: 정규화된 SLSA 기준값
- `oidc`: 정규화된 OIDC 기준값
- `mismatches`: 불일치 상세 목록

이를 통해 최종 Consumer Gate에서는 단순 실패 여부뿐 아니라, 어떤 필드가 어떤 값으로 충돌했는지까지 사용자에게 설명할 수 있다.

---

## Step 6: Schema Mapper 구현 완료

Track C의 parser와 validator가 각각 안정적으로 동작하게 된 뒤, 최종 Consumer Gate에서 사용할 수 있는 단일 출력 계약을 만들기 위해 `schema_mapper.py`를 구현했다.

이 모듈의 책임은 SLSA predicate, Fulcio OIDC claim, Rekor transparency log, cross-validation 결과를 하나의 안정적인 JSON schema로 직렬화하는 것이다. schema version은 `srp.track-c.v1`로 고정해 이후 Track A, Track B, Consumer Gate가 동일한 구조를 기준으로 데이터를 처리할 수 있도록 했다.

주요 구현 내용은 다음과 같다.

- `build_release_lineage_schema()` 함수 구현
- `build_error_schema()` 함수 구현
- package metadata를 `ecosystem`, `name`, `version`, `purl`로 정규화
- npm attestation API URL과 선택된 attestation index 기록
- SLSA predicate의 `repository`, `commit`, `workflow_path` 직렬화
- Fulcio OIDC의 `issuer`, `subject`, `subject_repo`, `subject_workflow` 직렬화
- GitHub custom OID extension을 `github_extensions` 하위 객체로 분리
- Rekor log 존재 여부, `logIndex`, `integratedTime` 직렬화
- Rule 5.4 `OIDC_MISMATCH` 검증 결과를 `validation.rules`에 구조화
- 수집 실패나 검증 불가 상태를 JSON error document로 표현

`schema_mapper.py`는 SRP(Single Responsibility Principle)에 맞춰 설계했다. 네트워크 호출, DSSE 파싱, certificate 파싱, Rekor 파싱, 검증 판단을 직접 수행하지 않고, 이미 계산된 parser output과 validator output을 최종 JSON 계약으로 매핑하는 역할만 담당한다.

이를 통해 Track C의 내부 구현이 바뀌더라도 외부 Consumer Gate는 `srp.track-c.v1` schema만 안정적으로 소비할 수 있다.

---

## Step 7: CLI 진입점 및 전체 파이프라인 통합 (main.py)

기존 `run_test.py`는 `vite@5.2.0`을 대상으로 동작을 확인하기 위한 하드코딩된 테스트 스크립트였다. 오늘 작업에서는 이 실험용 흐름을 production-ready CLI 진입점인 `main.py`로 승격했다.

`main.py`는 npm package name과 version을 인자로 받아 Track C 전체 pipeline을 실행한다.

주요 CLI 기능은 다음과 같다.

- positional argument로 npm package name 입력
- positional argument로 npm package version 입력
- `-o` 또는 `--output` 옵션으로 최종 JSON 파일 저장 지원
- `--timeout` 옵션으로 npm registry 요청 timeout 설정
- scoped package 예: `@scope/package` URL encoding 지원
- 성공 시 unified release lineage JSON을 stdout 또는 파일로 출력
- 실패 시에도 `build_error_schema()` 기반 JSON error document 출력
- 네트워크 오류, JSON 오류, DSSE 오류, OIDC 오류, Rekor 오류, validation 오류를 명확한 error boundary로 처리

실행 예시는 다음과 같다.

```bash
python main.py vite 5.2.0
python main.py vite 5.2.0 --output result.json
python main.py @scope/package 1.0.0 --timeout 30
```

`main.py`의 orchestration flow는 다음과 같다.

1. npm package name/version을 CLI 인자로 수신
2. npm attestation API URL 생성
3. npm registry에서 attestations 수집
4. attestation 배열 순회
5. 각 bundle에서 DSSE payload 추출
6. SLSA Provenance가 아닌 Publish Attestation은 건너뜀
7. SLSA predicate 핵심 필드 정규화
8. Fulcio OIDC certificate claim 추출
9. Rekor transparency log metadata 추출
10. Rule 5.4 `OIDC_MISMATCH` 교차 검증 수행
11. `schema_mapper.py`를 통해 최종 `srp.track-c.v1` JSON 생성
12. stdout 또는 `--output` 파일로 결과 출력

이제 Track C는 개별 parser와 테스트 스크립트의 조합이 아니라, 다른 트랙과 통합 가능한 CLI 도구 형태로 제공된다.

---

## End-to-End Pipeline 테스트

초기 end-to-end 검증은 `run_test.py`를 통해 수행했다. 이 스크립트는 `vite@5.2.0`을 하드코딩해 npm attestation API 호출, DSSE 추출, predicate 파싱, OIDC/Rekor 파싱, cross-validation까지 이어지는 흐름을 빠르게 검증하는 역할을 했다.

오늘 작업 이후 end-to-end 실행 기준은 `main.py`로 전환되었다.

현재 production-ready pipeline 흐름은 다음과 같다.

1. CLI에서 npm package/version 입력
2. npm attestation API에서 package/version의 attestation 목록 수집
3. 각 attestation bundle에서 DSSE envelope 추출
4. Base64 payload를 디코딩해 SLSA predicate 복원
5. 실제 SLSA Provenance인지 확인
6. SLSA predicate에서 `repository`, `commit`, `workflow_path` 추출
7. `verificationMaterial`에서 Fulcio OIDC claim 추출
8. `verificationMaterial`에서 Rekor `logIndex`, `integratedTime` 추출
9. SLSA predicate와 OIDC claim을 교차 검증
10. `schema_mapper.py`에서 `srp.track-c.v1` unified JSON으로 직렬화
11. stdout 또는 `--output` 파일로 결과 출력

`vite@5.2.0` 대상으로 전체 pipeline을 검증했으며, Fulcio OIDC extension과 Rekor metadata를 포함한 최종 JSON이 정상 생성되었다. 검증 결과는 `PASS`였고, Rekor `logIndex`는 `79706244`로 확인되었다.

또한 존재하지 않는 package나 legacy package처럼 Sigstore/SLSA provenance를 제공하지 않는 입력에 대해서도 프로그램이 비정상 종료되지 않고, `build_error_schema()` 기반의 구조화된 error document를 생성하는 것을 확인했다.

이제 Track C는 개별 parser 모음이 아니라, npm package attestation을 입력으로 받아 provenance 수집, 신원 추출, Rekor metadata 확인, OIDC mismatch 탐지, schema 직렬화까지 수행하는 하나의 collector pipeline으로 동작한다.

---

## 현재까지의 성과

현재까지 구현된 핵심 성과는 다음과 같다.

- Sigstore DSSE envelope 해체 가능
- Base64 payload 복원 및 in-toto Statement JSON 파싱 가능
- SLSA `predicate` 추출 가능
- SLSA predicate에서 `repository`, `commit`, `workflow_path` 정규화 가능
- npm API의 다중 attestation 구조 대응
- Publish Attestation과 실제 SLSA Provenance 구분 가능
- `verificationMaterial`에서 Fulcio x509 certificate chain 추출 가능
- Fulcio certificate에서 OIDC `issuer`와 `subject` 추출 가능
- GitHub Actions 관련 Fulcio custom OID extension 추출 가능
- OIDC subject 기반 `subject_repo`, `subject_workflow` 정규화 가능
- Rekor transparency log의 `logIndex`, `integratedTime` 추출 가능
- malformed bundle, certificate, tlog entry에 대한 custom exception 기반 오류 처리 구현
- SLSA predicate와 OIDC claim 간 repository/workflow 교차 검증 구현
- Rule 5.4 `OIDC_MISMATCH` 탐지 로직 구현
- `schema_mapper.py` 기반 `srp.track-c.v1` unified JSON schema 제공
- 성공 결과와 실패 결과를 동일한 출력 계약 안에서 표현 가능
- `main.py` 기반 production-ready CLI 도구 제공
- `-o`/`--output` 파일 저장 및 `--timeout` 설정 지원
- 네트워크, JSON, DSSE, OIDC, Rekor, validation, schema mapping 단계별 방어적 error boundary 구현
- `requirements.txt`를 통해 production dependency 명시
- `vite@5.2.0` 대상 end-to-end `PASS` 검증 완료
- 존재하지 않는 package 및 legacy package에 대한 graceful error document 생성 확인

---

## 다음 단계

Track C 자체 구현은 collector pipeline 수준까지 완료되었으므로, 다음 단계는 Track A, Track B와 통합해 최종 **Consumer Gate**를 구성하는 것이다.

1. Track A npm metadata collector와 통합

   Track A에서 수집한 package name, version, tarball integrity, registry metadata를 Track C의 attestation 수집 입력으로 연결한다. 이를 통해 특정 npm 패키지 버전에 대해 registry metadata와 Sigstore provenance를 같은 기준으로 비교할 수 있다.

2. Track B GitHub repository collector와 통합

   Track C가 추출한 `repository`, `commit`, `workflow_path`를 Track B로 전달해 실제 GitHub repository 상태를 확인한다. 예를 들어 commit 존재 여부, workflow file 존재 여부, branch/ref 일치 여부, repository visibility 및 ownership 정보를 검증할 수 있다.

3. Consumer Gate 정책 엔진 설계

   Track A, B, C의 결과를 하나의 policy decision으로 통합한다. 예를 들어 다음과 같은 조건을 gate rule로 정의할 수 있다.

   - npm package metadata와 SLSA subject 일치 여부
   - SLSA predicate와 Fulcio OIDC subject 일치 여부
   - Rekor transparency log 존재 여부
   - GitHub commit 및 workflow 존재 여부
   - repository ownership 또는 expected publisher policy 충족 여부

4. 위험도 기반 결과 모델 정의

   단순 `PASS`/`FAIL`뿐 아니라 `WARN`, `UNKNOWN`, `ERROR` 상태를 포함한 결과 모델을 설계한다. 예를 들어 Rekor log가 없으면 `FAIL`, workflow path를 OIDC에서 추출할 수 없으면 `WARN`, GitHub API 장애는 `UNKNOWN`으로 분리할 수 있다.

5. 최종 CLI 또는 API 인터페이스 구성

   최종 Consumer Gate는 `package@version`을 입력받아 Track A, B, C를 순차 또는 병렬로 실행하고, 사람이 읽을 수 있는 요약 결과와 기계가 처리할 수 있는 JSON 결과를 함께 출력하도록 구성한다.

---

## 정리

이번 단계에서 Track C는 Sigstore/Rekor Collector의 핵심 기능을 모두 갖추었다.

초기에는 DSSE bundle을 해체하고 SLSA predicate를 읽는 수준이었지만, 현재는 Fulcio OIDC certificate, GitHub custom OID extension, Rekor transparency log, SLSA predicate를 함께 분석해 서로의 주장을 교차 검증할 수 있다.

특히 `cross_validator.py`를 통해 **서명 주체의 OIDC 신원**과 **attestation payload의 빌드 출처**가 일치하는지 검증할 수 있게 되었고, 이는 공급망 공격에서 중요한 `OIDC_MISMATCH` 유형을 탐지하는 기반이 된다.

또한 `schema_mapper.py`와 `main.py`를 통해 Track C는 production-ready CLI와 stable JSON schema를 갖춘 통합 collector로 발전했다. 이제 이 모듈은 단독 검증 도구로 사용할 수 있을 뿐 아니라, Track A와 Track B의 결과를 결합하는 최종 Consumer Gate의 입력 신호로 바로 연결할 수 있다.

따라서 Track C는 이제 독립적인 provenance collector를 넘어, 최종 Consumer Gate에서 npm package release lineage를 판단하는 핵심 보안 신호 제공 모듈로 사용할 수 있다.
