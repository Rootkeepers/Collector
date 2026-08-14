# TrustGate AI 분석 사용설명서

이 문서는 대시보드에 추가된 LangGraph 기반 보조 분석을 설치하고 운영하는 방법을
설명한다. AI 분석은 npm·GitHub·Sigstore 증거와 6개 규칙이 만든 핵심 판정을
설명할 뿐이다. `PASS`, `RISK`, `UNVERIFIABLE (RISK)`를 바꾸거나 설치 차단을
해제하지 않는다.

## 1. 분석 흐름

Explorer의 **AI 분석** 버튼은 다음 작업을 실행한다.

1. 현재 결과와 이전 스캔을 비교해 판정·점수·수집기 상태의 회귀를 찾는다.
2. OSV에서 설치된 정확한 npm 버전의 알려진 취약점을 조회한다.
3. npm registry의 tarball을 임시 폴더에 안전하게 풀고 SRI 무결성을 검증한다.
4. lifecycle script와 Semgrep으로 변조·위험 API 신호를 2차 분석한다.
5. Groq Free tier 생성형 AI가 이상 점수와 증거를 받아 한국어 설명·조치·신뢰도를 만든다.

패키지 코드는 설치하거나 실행하지 않는다. Groq에는 소스 원문과 lifecycle command
본문을 보내지 않고 정규화된 증거 메타데이터만 전송한다. 키 누락, 무료 한도 초과,
네트워크 오류가 생기면 로컬 증거 추론으로 자동 전환한다.

## 2. 설치

PowerShell에서 프로젝트 루트로 이동한 뒤 설치한다.

```powershell
cd C:\Users\iljae\Downloads\Collector-main\Collector-main
py -m pip install -e ".[sast,dev]"
Copy-Item .env.example .env
```

Semgrep을 제외한 분석만 필요하면 `py -m pip install -e ".[dev]"`를 사용한다.
Semgrep이 없을 때에도 이력 비교, OSV, SRI, lifecycle 검사는 동작하며 화면에는
SAST `PARTIAL` 상태가 표시된다.

Windows Python의 Scripts 폴더가 `PATH`에 없더라도 같은 Python에 설치된
`semgrep.exe`는 자동 탐지한다. 다른 실행 파일을 쓰려면
`TRUSTGATE_SEMGREP_COMMAND=C:/path/to/semgrep.exe`로 지정한다.

## 3. Groq 무료 API 설정

`.env.example`을 복사하면 다음 설정이 기본으로 적용된다.

```env
TRUSTGATE_AI_PROVIDER=groq
GROQ_API_KEY=gsk_발급받은_키
TRUSTGATE_GROQ_MODEL=openai/gpt-oss-20b
TRUSTGATE_ENABLE_AI=auto
```

[Groq API Keys](https://console.groq.com/keys)에서 Free plan 키를 만든다. 결제수단을
등록하지 않은 Free plan은 공개된 무료 rate limit 안에서만 동작하며 유료 요청으로
자동 전환되지 않는다. 정확한 한도는 Groq Console의 Limits에서 확인한다.

Groq에는 다음 정규화된 근거만 보낸다.

- 이전 스캔 점수의 중앙값·MAD 기반 이상 점수
- 판정 악화, 신규 활성 규칙, 수집기 회귀
- OSV 취약점 심각도와 모든 권고를 벗어나는 수정 버전
- npm SRI 상태와 Semgrep의 규칙 ID·심각도·파일 경로·행·메시지

소스 내용, lifecycle command 본문, API 키는 전송 payload에 넣지 않는다. 일반 추론
요청은 Groq 정책상 기본적으로 보관되지 않으며 `store=false`를 함께 보낸다.

### 무료 로컬 폴백

다음 설정을 사용하면 Groq를 전혀 호출하지 않는다.

```env
TRUSTGATE_AI_PROVIDER=local
```

Groq 모드에서도 API 실패 시 자동으로 로컬 엔진을 사용하고 화면에 폴백 원인을
표시한다. 분석 자체를 끄려면 `TRUSTGATE_ENABLE_AI=0`을 사용한다.

### 선택: OpenAI 유료 경로

기본 기능에는 필요하지 않다. 별도로 원할 때만 다음처럼 설치하고 설정한다.

```powershell
py -m pip install -e ".[openai]"
```

```env
TRUSTGATE_AI_PROVIDER=openai
OPENAI_API_KEY=발급받은_키
TRUSTGATE_AI_MODEL=gpt-5.4-nano
```

외부 모드도 소스 원문과 lifecycle command 본문은 보내지 않고 `store=False`를
사용한다. API 사용료와 한도는 해당 API 프로젝트에 속한다.

## 4. 대시보드 사용

```powershell
trustgate up
```

브라우저에서 `http://localhost:8000`을 연다.

1. Dashboard에서 `패키지@버전`을 입력하고 스캔한다.
2. Package Explorer에서 해당 행을 펼친다.
3. **AI 분석** 탭을 누른다.
4. 이력 이상 점수, OSV 취약점, 소스/SAST, 조치 제안, 설명 엔진 상태를 확인한다.
5. 수정 버전 설치 버튼은 다시 핵심 계보 검증을 실행하며, 결과가 `PASS`일 때만
   실제 npm 설치를 허용한다.

설명 엔진 상태의 의미는 다음과 같다.

| 상태 | 의미 | 조치 |
|---|---|---|
| `GROQ · AVAILABLE · FREE_TIER` | 무료 API 구조화 설명 성공 | 근거 카드와 함께 검토 |
| `LOCAL · AVAILABLE · FREE` | Groq 미설정/오류로 로컬 폴백 | 폴백 원인을 확인하되 분석은 사용 가능 |
| `OPENAI · AVAILABLE` | 명시적으로 선택한 외부 설명 성공 | 근거 카드와 함께 검토 |
| `DISABLED` | 분석 기능을 껐음 | `TRUSTGATE_ENABLE_AI` 확인 |
| `ERROR` | provider 설정 또는 선택적 외부 API 실패 | 서버 로그의 오류 종류 확인 |

## 5. 취약 버전 모니터링

Installed Packages의 **취약 버전 모니터링** 버튼은 현재 프로젝트의
`package-lock.json`에 고정된 버전을 OSV로 조회한다. CLI에서도 같은 기능을 쓴다.

```powershell
trustgate monitor --project C:\path\to\my-app
trustgate monitor --project C:\path\to\my-app --json
```

대시보드가 실행 중이면 기본 60분마다 갱신한다. 주기를 바꾸거나 끌 수 있다.

```env
TRUSTGATE_PROJECT_DIR=C:/path/to/my-app
TRUSTGATE_MONITOR_INTERVAL_MINUTES=30
# 0이면 자동 점검 중지
```

`ACTION_REQUIRED`는 알려진 취약 버전이 있다는 뜻이고, `PARTIAL`은 일부 OSV 조회가
실패했다는 뜻이다. 자동 업그레이드는 하지 않는다.

## 6. 테스트

비용이 들지 않는 전체 자동 테스트와 문법 검사는 다음과 같다.

```powershell
py -m pytest -q
node --check src\rootkeepers\dashboard\static\app.js
py -m compileall -q src
semgrep scan --validate --config src\rootkeepers\analysis\rules\npm-supply-chain.yml
```

무료 Groq API 테스트는 키와 실행 플래그를 모두 명시한 경우에만 한 번 호출한다.

```powershell
$env:ROOTKEEPERS_RUN_LIVE_GROQ_TESTS="1"
$env:TRUSTGATE_ENABLE_AI="1"
$env:TRUSTGATE_AI_PROVIDER="groq"
py -m pytest -q -m live_groq tests\test_live_groq_integration.py
```

이 선택 테스트는 Groq 구조화 출력과 핵심 `RISK` 판정 보존을 검증한다.

## 7. 문제 해결

- Groq가 로컬로 폴백함: 화면의 `GROQ API 폴백` 원인을 확인한다.
- `GROQ_API_KEY_MISSING`: 저장소 루트 `.env`의 키를 확인한다.
- Groq HTTP 401: 키가 잘못되었거나 폐기됐다. Free plan 키를 다시 발급한다.
- Groq HTTP 429: 무료 RPM/RPD/토큰 한도다. 기다리면 로컬 폴백으로 계속 동작한다.
- `UNSUPPORTED_AI_PROVIDER`: `groq`, `local`, `free`, `openai` 중 하나를 사용한다.
- 외부 모드의 `OPENAI_API_KEY_MISSING`: `.env` 또는 환경변수를 확인한다.
- 외부 모드 HTTP 401/429: API 키·프로젝트 한도·결제 상태를 확인하거나 `local`로 복귀한다.
- SAST `PARTIAL`: `semgrep --version`을 확인하고 `.[sast]` 옵션을 다시 설치한다.
- SRI `MISMATCH`: 분석 결과를 신뢰하지 말고 설치를 중단한 뒤 registry 메타데이터와
  캐시·프록시를 점검한다.
- OSV `ERROR`/`UNAVAILABLE`: 네트워크 연결 후 다시 실행한다. 이 상태가 설치를
  허용하는 근거가 되지는 않는다.

## 8. 운영 원칙

- AI/OSV/SAST는 보조 정보이며 핵심 판정의 권한을 갖지 않는다.
- 핵심 판정은 fail-closed다. `PASS`가 아닌 모든 결과는 설치가 차단된다.
- 기본 Groq Free plan은 무료 한도 안에서만 외부 생성형 설명을 사용한다.
- Groq 장애나 한도 초과 시 로컬 폴백이 핵심 기능을 유지한다.
- 선택적 API 키는 서버에서만 읽고 대시보드 응답이나 로그에 넣지 않는다.
- 조치 제안은 자동 실행하지 않고, 수정 버전도 핵심 검증을 다시 통과해야 한다.
