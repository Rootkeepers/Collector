# Rootkeepers Collector

## Step 9: 메인 엔진 통합 및 파이프라인 구축 (Integration & Orchestration)

이번 단계에서는 독립적으로 동작하던 세 개의 수집 모듈을 하나의 실행 흐름으로 통합하여, npm 릴리스의 계보 정보를 단일 JSON 리포트로 생성하는 메인 오케스트레이션 엔진을 구축했다. 기존 Track A, Track B, Track C는 각각 npm 메타데이터, GitHub 증거, Sigstore/Rekor 검증 정보를 수집하는 역할을 유지하되, 이제 `main.py`를 통해 하나의 파이프라인으로 실행된다.

### 1. 통합 파이프라인 구축

루트 수준의 `main.py`를 단일 CLI 진입점으로 추가했다. 사용자는 패키지명과 버전을 인자로 전달하여 전체 릴리스 계보 수집 파이프라인을 실행할 수 있다.

파이프라인은 npm collector를 먼저 실행한다. Track A는 npm registry에서 대상 패키지와 버전의 메타데이터를 조회하고, 이후 단계에 필요한 핵심 값인 `gitHead`와 `repository_url`을 추출한다. 메인 엔진은 이 값을 기반으로 GitHub 저장소 식별자(`owner/repo`)를 정규화한 뒤, GitHub collector와 Sigstore collector를 실행한다.

이 구조를 통해 각 collector는 자신의 책임을 유지하면서도, 전체 시스템은 하나의 릴리스 계보 리포트를 생성하는 일관된 애플리케이션처럼 동작한다.

### 2. Graceful Fallback 및 표준 상태 리포팅

메인 엔진은 개별 트랙의 실패가 전체 파이프라인 실패로 전파되지 않도록 설계되었다. 예를 들어 Sigstore attestation API가 `404 Not Found`를 반환하거나, GitHub collector 실행 시 `GITHUB_TOKEN`이 설정되지 않은 경우에도 엔진은 중단되지 않는다.

각 트랙의 실행 결과는 표준 JSON 구조 안에 `SUCCESS`, `SKIPPED`, `ERROR`, `UNVERIFIABLE` 같은 상태로 기록된다. 실패한 트랙은 `error.type`, `error.reason`, `error.message`를 포함하며, 성공한 트랙의 데이터는 그대로 보존된다. 이 방식은 부분 성공 결과를 분석 가능하게 유지하고, 외부 API 오류나 인증 문제를 디버깅할 수 있는 명확한 근거를 제공한다.

최종 리포트의 `summary.track_statuses` 필드는 전체 실행 결과를 빠르게 확인할 수 있는 요약 지점이다. 이를 통해 CI, QA 자동화, 후속 판정 로직에서 각 collector의 상태를 안정적으로 판별할 수 있다.

### 3. 보안 및 설정 관리 정리

프로젝트 구조를 단일 애플리케이션 형태로 정리하기 위해 각 collector 하위에 분산되어 있던 `.gitignore`와 `requirements.txt`를 루트 수준으로 통합했다. 이제 의존성 설치와 ignore 정책은 프로젝트 루트에서 일관되게 관리된다.

GitHub API 인증 정보는 코드에 직접 작성하지 않고 `.env` 파일에서 로드하도록 `python-dotenv` 지원을 추가했다. `GITHUB_TOKEN`은 로컬 개발 환경이나 CI 환경변수로 주입되며, `.env` 파일은 `.gitignore`에 포함되어 저장소에 커밋되지 않는다.

커밋 가능한 예시 파일로 `.env.example`을 제공하여 필요한 환경변수 이름은 문서화하되, 실제 토큰 값은 저장소에 남기지 않는 구성을 유지한다.

### 4. E2E 자동화 테스트 추가

통합 파이프라인의 실제 동작을 검증하기 위해 `tests/test_e2e_pipeline.py`를 추가했다. 이 테스트는 `express` 패키지의 `4.18.2` 버전을 대상으로 통합 오케스트레이터를 실행하고, npm과 GitHub 트랙이 정상적으로 성공하는지 확인한다.

테스트는 `GITHUB_TOKEN` 또는 `E2E_GITHUB_TOKEN` 환경변수를 사용한다. 토큰이 없는 환경에서는 테스트를 안전하게 건너뛰며, 토큰이 설정된 환경에서는 실제 npm registry 및 GitHub API를 호출해 데이터 흐름과 인증 구성이 정상인지 검증한다.

이 E2E 테스트는 단순한 단위 테스트가 아니라, Track A에서 추출한 `gitHead`와 `repository_url`이 Track B로 전달되는 전체 연결 흐름을 확인한다는 점에서 통합 품질을 검증하는 기준점 역할을 한다.

### How to Run (실행 방법)

#### 1. 의존성 설치

프로젝트 루트에서 다음 명령어를 실행한다.

```powershell
python -m pip install -r requirements.txt
```

#### 2. `.env` 파일 설정

`.env.example`을 복사하여 로컬 전용 `.env` 파일을 만든다.

```powershell
Copy-Item .env.example .env
```

생성된 `.env` 파일에 GitHub 토큰을 설정한다.

```env
GITHUB_TOKEN=ghp_your_github_token_here
```

`.env` 파일은 `.gitignore`에 포함되어 있으므로 저장소에 커밋하지 않는다. CI 환경에서는 `.env` 파일 대신 secret 또는 환경변수 설정 기능을 사용해 `GITHUB_TOKEN`을 주입하는 방식을 권장한다.

#### 3. 통합 CLI 실행

다음 명령어로 `express@4.18.2` 릴리스 계보 리포트를 생성한다.

```powershell
python main.py express 4.18.2
```

결과를 파일로 저장하려면 `-o` 옵션을 사용한다.

```powershell
python main.py express 4.18.2 -o release_lineage_report.json
```

#### 4. E2E 테스트 실행

GitHub 토큰이 `.env` 또는 환경변수에 설정된 상태에서 다음 명령어를 실행한다.

```powershell
python -m pytest tests/test_e2e_pipeline.py -v
```

테스트는 최종 JSON 리포트의 `summary.track_statuses.github` 값이 `SUCCESS`인지 확인하여 GitHub 인증과 API 호출이 정상 동작하는지 검증한다. 또한 `summary.track_statuses.npm` 값이 `SUCCESS`인지 확인하여 npm collector와 오케스트레이터의 기본 데이터 흐름이 정상인지 검증한다.
