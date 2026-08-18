# TrustGate — npm 공급망 계보 검증 도구

npm 패키지를 설치하기 **전에** 그 릴리스가 어디서 어떻게 만들어졌는지(계보)를
npm·GitHub·Sigstore 세 곳에서 수집하고, 6개 공급망 규칙으로 채점해 위험하면
설치를 막는다. 대시보드의 LangGraph 보조 분석은 스캔 이력·OSV·Semgrep·Groq
무료 API 설명을 결합하지만, 이 핵심 판정이나 설치 게이트를 변경하지 않는다.

`event-stream`(2018), `ua-parser-js`(2021) 같은 사고는 전부 평소와 똑같은
`npm install` 한 번으로 성립했다. 그래서 이 도구는 "무엇이 나쁜가"가 아니라
**"평소와 무엇이 달라졌는가"** 를 본다.

---

## 빠른 시작

```bash
pip install -e .
cp .env.example .env          # GITHUB_TOKEN 채우기
trustgate up
```

→ http://localhost:8000 · 문제가 있으면 `trustgate doctor`

---

## 요구 사항

- Python 3.10+
- Node.js / npm
- GitHub Personal Access Token (fine-grained, "Public Repositories (read-only)")
- 선택: Semgrep (`pip install -e ".[sast]"`) — npm 소스 2차 정적 분석
- 기본: Groq Free tier API — 결제수단·모델 다운로드 없이 생성형 설명
- 폴백: 키 누락·무료 한도 초과 시 로컬 증거 추론으로 자동 전환
- 선택: `pip install -e ".[openai]"` — 명시적으로 고른 경우만 외부 생성형 설명

AI 키 설정, 화면 사용, 모니터링, 실 API 테스트와 문제 해결은
[AI 분석 사용설명서](docs/AI_ANALYSIS_GUIDE.md)에 순서대로 정리되어 있다.

## 설치

레포 루트(`pyproject.toml`이 있는 위치)에서:

```bash
pip install -e .
```

최신 Debian/Ubuntu는 시스템 Python에 `pip install`을 직접 하는 걸 막아놓는다
(PEP 668, `externally-managed-environment` 에러). 그럴 때는 `--user`를 붙이거나
[pipx](https://pipx.pypa.io/)를 쓴다. pipx는 패키지마다 격리된 가상환경을 만들면서도
커맨드는 PATH에서 바로 잡히게 해 준다.

```bash
pipx install -e . && pipx ensurepath
```

새 터미널을 열면 `trustgate`, `safe-npm`, `safe-npm-setup` 세 커맨드가 잡힌다.

## GitHub 토큰 설정

```bash
cp .env.example .env
```

```env
GITHUB_TOKEN=ghp_your_github_token_here
```

`.env`는 **저장소 루트 한 곳만** 읽는다. `.gitignore`에 포함되어 커밋되지 않는다 —
각자 자기 컴퓨터에 자기 토큰으로 만들어야 한다.

---

## trustgate 명령

```bash
trustgate doctor    # 환경이 제대로 물려 있는지 진단
trustgate up        # 콘솔을 백그라운드로 실행
trustgate down      # 종료
trustgate status    # 실행 상태
trustgate scan lodash react@18.2.0   # 설치하지 않고 판정만
trustgate install lodash             # 검사 후 통과하면 설치
trustgate monitor --project ./my-app # 설치된 정확한 버전을 OSV로 점검
```

`doctor`가 진단하는 것 — 대부분의 사고는 기능 버그가 아니라 환경 불일치다.

| 항목 | 잡아내는 문제 |
|---|---|
| 콘솔 코드 | 코드를 pull하고 재시작하지 않아 새 API가 없는 상태 |
| safe-npm | 클론이 여러 개일 때 엉뚱한 사본을 실행 |
| npm shim | shim 미설치 / 여러 디렉터리에 잔재 / PATH 순서 |
| DB 불일치 | 콘솔과 터미널이 서로 다른 이력 DB를 봄 |
| 토큰 · 검사 대상 | `GITHUB_TOKEN` 누락, `package.json` 없음 |

각 항목에 고칠 명령이 함께 나오고, 문제가 있으면 종료 코드 1을 낸다.

PID와 로그는 `~/.trustgate/`에 모인다 (`console.pid`, `console.log`).
`TRUSTGATE_RUNTIME_DIR`로 바꿀 수 있다.

---

## npm 인터셉트 활성화

```bash
safe-npm-setup
```

PATH 우선순위가 앞선 디렉터리(`~/.local/bin` 등)에 `npm` shim을 설치한다. 이후
`npm install <패키지>`라고만 쳐도 검사를 거친 뒤 실제 npm에 위임된다.

새 디렉터리를 만든 경우 셸 rc 파일에 PATH 설정이 추가되므로, 새 터미널을 열거나
`source` 해야 적용된다. 제거는 `safe-npm-setup --uninstall`.

shim 없이 직접 검사만 하려면 `safe-npm install <패키지명>`.

### 커맨드별 검사 범위

| 커맨드 | 설치 전 | 설치 후 |
|---|---|---|
| `npm install <패키지>` | 지목한 패키지의 계보(Track A/B/C) + 쿨다운 + 6규칙 → **RISK면 차단** | 함께 들어온 패키지의 알려진 취약 버전 → 경고 |
| `npm install` (인자 없음), `npm ci` | ① lock 전체(전이 포함)의 알려진 취약 버전 → 경고<br>② 새로 들어오는 패키지의 계보 → **RISK면 차단** | 새로 들어온 패키지 → 경고 |
| `run`, `publish` 등 | 통과 | — |

인자 없는 `npm install`과 `npm ci`는 clone 직후·pull 직후에 가장 자주 실행되는
형태이면서, 깔리는 것은 직접 의존성이 아니라 lock에 적힌 전이 의존성 전체다.
여기에 계보 수집을 그대로 걸면 설치가 사실상 멈추므로, 비용이 요청 1회로 끝나는
OSV 일괄 조회만 붙였다. lock이 없으면 `npm install --package-lock-only`로 **설치
없이** lock만 먼저 만들어, 설치 전에 목록을 확인한다.

#### 계보 검증 대상 고르기

취약점 점검만으로는 "평소와 무엇이 달라졌는가"를 못 본다. 그래서 계보 수집도
붙이되, 대상을 두 단계로 좁힌다.

1. **이미 같은 버전이 깔려 있는 것 제외.** lock의 키가 곧 설치 경로라
   `node_modules/<경로>/package.json`의 버전을 그대로 비교하면 된다. 같은
   버전이 이미 있으면 이번 설치로 새 코드가 들어오지 않는다. pull 이후의
   `npm install`은 보통 여기서 한 자릿수로 줄어든다.
2. **직접 의존성 우선, 그다음 개수 상한.** `TRUSTGATE_LINEAGE_MAX`(기본 10)로
   조절하고, 0이면 이 단계를 끈다. 상한에 걸려 못 본 개수는 항상 출력한다.

상한이 필요한 이유는 `scan_package()`가 모듈 전역 락으로 직렬화되어 있어서다
(`scanning._scan_lock`). 동시 실행이 안 되므로 소요 시간이 패키지 수에 그대로
비례하고, 그 시간은 설치 앞단에서 사용자가 기다리는 시간이다.

**RISK면 차단하고, UNVERIFIABLE은 경고만 한다.** 지목 설치(`gate_install`)가
PASS 아닌 것을 전부 막는 것과 다르다. 전이 의존성에는 GitHub 저장소가 없거나
Sigstore 서명이 없는 패키지가 흔해서, UNVERIFIABLE까지 막으면 정상 프로젝트의
첫 설치가 거의 항상 멈춘다. 그러면 도구를 끄게 되고, 막아야 할 RISK도 같이
놓친다.

출력은 검사한 것과 안 한 것을 항상 숫자로 함께 적는다.

```
[확인] 전이 의존성 포함 847개 · 알려진 취약 버전 없음
[계보] 새로 들어오는 패키지 10개의 계보를 수집합니다 (패키지당 수 초, 순차 실행)...
  (1/10) express@4.18.2
    [PASS] score=88
  ...
[미검사] 나머지 23개는 상한(TRUSTGATE_LINEAGE_MAX=10)에 걸려 계보를 보지 않았습니다.
[범위] 계보 검증: 10개 · 알려진 취약 버전만 확인: 837개 (전체 847개)
```

전체 계보까지 보려면 `safe-npm install <패키지명>`으로 지목한다.

### 설치 후 재점검

`safe-npm install express`가 계보를 검증하는 것은 **express 하나**다. 그런데
npm이 실제로 깐 것은 express와 그 서브트리 전체이고, 설치 스크립트는 그 전체가
돌린다. 지목 설치에도 같은 격차가 있는 셈이다.

설치 전에 서브트리를 알려면 의존성 해석을 먼저 돌려야 해서 응답 시간이 그만큼
늘어난다. 대신 설치 직후 lock을 다시 읽어 **변화분**을 점검한다. 이미 깔린
뒤라 차단은 못 하지만, 무엇이 함께 들어왔는지는 알 수 있다.

```
[사후] 이번 설치로 패키지 41개가 새로 들어왔습니다 (전이 의존성 포함). ...
[경고] 새로 들어온 41개 중 2개가 알려진 취약 버전입니다.
  - qs@6.9.7 · 1건 · 조치: 6.9.8
[미검사] 새로 들어온 41개에 대해 계보 검증(Track A/B/C)은 수행되지 않았습니다.
```

전체가 아니라 변화분만 보는 이유는 비용이 아니라 신호 대 잡음이다. 매번 lock
전체를 경고하면 늘 같은 목록이 나와서 곧 무시된다. 변화가 없으면 아무것도
출력하지 않는다.

`TRUSTGATE_BULK_STRICT=1`이면 새 취약 패키지가 들어왔을 때 종료 코드가 1이
된다. 설치는 이미 끝난 뒤이므로 차단이 아니라 CI 실패 신호다.

알려진 취약 버전이 하나라도 있으면 설치를 막고 싶은 환경(CI 등)은
`TRUSTGATE_BULK_STRICT=1`로 켠다. 기본이 경고인 이유는, 규모가 있는 레포라면
알려진 CVE가 늘 몇 개씩 걸려서 기본 차단이 곧 도구 우회로 이어지기 때문이다.

---

## 웹 대시보드

`trustgate up` 후 http://localhost:8000.

| 화면 | 하는 일 |
|---|---|
| **Dashboard** | 패키지 스캔 실행, 판정 요약과 최근 스캔 |
| **Package Explorer** | 스캔한 패키지 목록. 규칙·증거·리포트와 LangGraph AI 분석(이력/OSV/SAST/조치)이 펼쳐진다 |
| **Installed Packages** | 설치 버전 · 최신 버전 · 마지막 판정 · 쿨다운 · 알려진 취약점을 비교하고, 수정 버전을 핵심 검증 후 설치 |
| **History** | 스캔·설치·차단 이력과 일자별 활동 |

Explorer와 Installed Packages는 이력 DB를 함께 읽는다. 그래서 **터미널에서
`npm install`한 결과도 화면에 나타난다.** 이번 세션의 라이브 스캔은 `LIVE`,
이력에서 되살린 것은 `기록` 태그로 구분된다.

### 이력은 어디에 남는가

```
콘솔 켜짐  →  safe-npm ──HTTP──> 콘솔 ──> SQLite
콘솔 꺼짐  →  safe-npm ─────────────────> SQLite (직접 기록)
```

기본 위치는 `~/.trustgate/history.sqlite3` — `TRUSTGATE_DB_PATH`로 바꾼다.

**콘솔이 꺼져 있어도 이력은 남는다.** 전송에 실패하면 CLI가 같은 DB에 직접
기록한다. 콘솔과 터미널이 서로 다른 `TRUSTGATE_DB_PATH`를 보면 기록이 갈리는데,
`trustgate doctor`가 그 경우를 경고한다.

### LangGraph 보조 분석

Explorer의 **AI 분석**은 다음 그래프를 실행한다.

1. 현재 핵심 판정과 이전 스캔을 비교해 verdict/점수/수집기 회귀를 감시한다.
2. OSV에 정확한 npm 버전을 조회하고, 여러 권고가 있으면 모든 영향 범위를
   벗어나는 가장 높은 수정 버전을 제시한다.
3. npm tarball의 registry host와 SRI 무결성을 확인하고, 경로 탈출·링크·압축 폭탄을
   막은 임시 폴더에만 추출한다. 패키지는 설치하거나 실행하지 않는다.
4. Semgrep과 lifecycle-script 검사를 통해 위험 API·설치 스크립트를 2차 검토한다.
5. Groq Free tier의 `openai/gpt-oss-20b`가 정규화된 메타데이터로 한국어 구조화
   설명·조치·신뢰도를 생성한다. 소스 원문은 전송하지 않으며, API를 사용할 수 없으면
   로컬 증거 추론기로 자동 전환한다.

LangGraph/OSV/Semgrep/설명 엔진 상태는 각각 표시된다. 어느 실패도 6규칙 결과를
지우거나 설치를 허용하지 않는다. Ollama와 packJ 연동은 사용하지 않는다.

Installed Packages의 OSV 스냅샷은 대시보드 실행 중 기본 60분마다 갱신된다.
`TRUSTGATE_MONITOR_INTERVAL_MINUTES=0`이면 주기 점검을 끄며, 수동 버튼과
`trustgate monitor`는 계속 사용할 수 있다. 조치는 자동 설치가 아니라 사용자가
명시적으로 누른 뒤 기존 계보 검증에서 `PASS`한 수정 버전에만 적용된다.

---

## 두 가지 사용 방식

| | 방법 | 특징 |
|---|---|---|
| **웹 대시보드** | `trustgate up` → localhost:8000 | 스캔·판정 근거 열람·설치·이력을 화면에서 |
| **터미널 CLI** | `npm install <pkg>` (shim) 또는 `trustgate install <pkg>` | 설치 전 검사 후 통과 시 실제 npm에 위임 |

둘은 **같은 판정 엔진**([scanning.py](src/rootkeepers/interceptor/scanning.py))을 쓴다.
같은 패키지에 대해 터미널과 대시보드의 결과가 갈리지 않는다.

---

## 6개 판정 규칙

| 규칙 | 무엇을 보는가 |
|---|---|
| `orphan_release` | 릴리스의 `gitHead`가 GitHub에 실제로 존재하는가 |
| `unreviewed` | 리뷰 없이 들어간 변경인가 |
| `workflow_drift` | 빌드 워크플로 경로가 과거와 달라졌는가 |
| `oidc_mismatch` | 서명 신원(OIDC)이 과거 릴리스와 다른가 |
| `unexpected_builder` | 평소와 다른 사람/시스템이 배포했는가 |
| `tag_identity_drift` | 태그·배포자 조합이 과거 패턴에서 벗어났는가 |

규칙별로 **PASS / WARN / RISK / UNVERIFIABLE** 밴드가 나온다.
비교할 과거가 없으면 감점하지 않고 `UNVERIFIABLE`로 남긴다 —
**모르는 것을 안전하다고 속이지 않기 위해서다.**

### 최종 판정

| 판정 | 의미 | 설치 차단 여부 |
|---|---|---|
| `PASS` | 계보 검증 통과 | 진행 |
| `RISK` | 규칙 위반 탐지 (예: OIDC mismatch) | **차단** |
| `UNVERIFIABLE (RISK)` | 쿨다운 미경과 또는 규칙 증거/기준선 부족 | **차단** |

패키지 배포 후 7일간은 계보 수집을 건너뛰고 관찰 기간으로 처리한다
(`COOLDOWN_DAYS`, [cooldown.py](src/rootkeepers/interceptor/cooldown.py)).

설치 게이트는 fail-closed다. 규칙 하나라도 `RISK` 밴드이거나 하나라도 검증할 수
없으면 설치를 막는다. 75점과 2/2 corroboration 값은 대시보드 우선순위와 감사용
메타데이터이며 설치 허용 조건이 아니다. AI/SAST/OSV 결과도 이 결정을 덮어쓰지 않는다.

---

## 현재 한계

**6규칙이 전부 평가되지는 않는다.** 대부분의 규칙은 절대적 나쁨이 아니라 **변화**를
보므로, 비교할 과거(기준선)가 없으면 감점하지 않고 `UNVERIFIABLE`로 남는다.
얼마나 풀리는지는 `TRUSTGATE_BASELINE`이 정한다.

| 설정 | 추가 API 호출 | 평가 가능 (실측: vite@8.2.1, 최근 5개 릴리스) |
|---|---|---|
| `off` | 0 | 1/6 |
| `npm` | 0회 (패키지 문서에 이미 포함) | 3/6 |
| `sigstore` **(기본)** | 릴리스당 1회 | **4/6** |

`orphan_release`의 거버넌스 부분과 `unreviewed`는 기본 설정에서도 아직
`UNVERIFIABLE`이다. 과거 릴리스의 커밋·PR·리뷰어 이력이 필요한데 릴리스당 GitHub
API가 약 5회 더 들어 캐시 설계가 선행되어야 한다
([baseline.py](src/rootkeepers/interceptor/baseline.py)). 버그가 아니라 로드맵상
다음 단계다. 자세한 내용은
[dashboard/README.md](src/rootkeepers/dashboard/README.md)에 있다.

**이력에서 되살린 행은 증거 JSON·리포트 탭이 비어 있다.** DB에는 판정·점수·규칙·
트랙 상태만 저장하고 증거 원문과 파이프라인은 남기지 않는다. 라이브 스캔(`LIVE`)은
전부 나온다.

---

## 구조

```
Collector/
├── .env.example                                설정 (토큰·검사 대상)
├── tests/                                      shim 회귀 테스트 · sigstore 수동 점검
├── requirements.txt · pyproject.toml · README.md
│
└── src/rootkeepers/                            ── 파이썬 패키지 전부
    ├── cli.py               `trustgate` 진입점 — 실행·정지·진단
    ├── analysis/            LangGraph · Groq 무료 API/로컬 폴백 · OSV · SAST
    ├── paths.py             저장소 경로 · `.env` 로딩 (세 패키지가 모두 씀)
    │
    ├── collectors/          ── 계보 수집 (Track A/B/C)
    │   ├── npm/                 Track A: 레지스트리 메타데이터, gitHead, 배포자
    │   ├── github/              Track B: 커밋·태그·워크플로 증거
    │   └── sigstore/            Track C: Rekor 투명성 로그, SLSA provenance
    │
    ├── interceptor/         ── 판정 · 설치 게이트 · 터미널 CLI
    │   ├── scanning.py          스캔 진입점 — CLI와 대시보드가 함께 쓴다
    │   ├── detailed_rule_engine.py  6규칙 채점 엔진
    │   ├── baseline.py          과거 릴리스 수집 — "평소"의 기준선
    │   ├── lineage.py           세 트랙을 하나의 계보로 통합
    │   ├── cooldown.py          신버전 관찰 기간(7일) 게이트
    │   ├── cooldown_gate.py     기준선·신버전 모두 PASS면 조기 승인
    │   ├── bulk_gate.py         인자 없는 install·ci의 lock 기준 일괄 점검
    │   ├── safe_npm.py          검사 후 진짜 npm에 위임
    │   ├── reporting.py         대시보드 전송 + 콘솔이 없으면 로컬 기록
    │   ├── inventory.py         설치된 패키지 목록 읽기 (네트워크 없음)
    │   ├── global_npm.py        전역 설치 목록 읽기 (npm ls -g)
    │   ├── shim_installer.py    npm shim 설치/제거 (safe-npm-setup)
    │   └── __main__.py          safe-npm 진입점
    │
    └── dashboard/           ── 웹 대시보드 (포트 8000)
        ├── server.py            HTTP API + 정적 서빙
        ├── store.py             이력 SQLite
        ├── background.py        백그라운드 실행 · PID · 로그
        ├── README.md            화면·환경변수·기준선 설명
        └── static/              브라우저로 나가는 것만
            ├── console.html · app.css · app.js
            └── fonts/           Inter · JetBrains Mono
```

각 collector 하위 폴더의 `README.md`에는 해당 모듈의 상세 개발 기록이 있다.

---

## ⚠️ 보안

콘솔은 **인증이 없고 패키지 설치를 실행할 수 있다.** 반드시 `127.0.0.1`에만
노출할 것 (`trustgate up` 기본값이 그렇게 되어 있다).
공개 네트워크에 열면 안 된다.
