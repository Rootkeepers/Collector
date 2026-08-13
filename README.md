# TrustGate — npm 공급망 계보 검증 도구

npm 패키지를 설치하기 **전에** 그 릴리스가 어디서 어떻게 만들어졌는지(계보)를
npm·GitHub·Sigstore 세 곳에서 수집하고, 6개 공급망 규칙으로 채점해 위험하면
설치를 막는다.

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
`install`/`i`가 아닌 서브커맨드(`run`, `ci` 등)는 검사 없이 통과한다.

새 디렉터리를 만든 경우 셸 rc 파일에 PATH 설정이 추가되므로, 새 터미널을 열거나
`source` 해야 적용된다. 제거는 `safe-npm-setup --uninstall`.

shim 없이 직접 검사만 하려면 `safe-npm install <패키지명>`.

---

## 웹 대시보드

`trustgate up` 후 http://localhost:8000.

| 화면 | 하는 일 |
|---|---|
| **Dashboard** | 패키지 스캔 실행, 판정 요약과 최근 스캔 |
| **Package Explorer** | 스캔한 패키지 목록. 행을 클릭하면 규칙별 점수·증거·리포트가 펼쳐진다 |
| **Installed Packages** | `package.json`을 읽어 설치 버전 · 최신 버전 · 마지막 판정 · 쿨다운을 비교하고, 그 자리에서 검증 후 설치 |
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
| `UNVERIFIABLE` | 쿨다운 미경과 또는 계보 수집 불가 | 경고만 출력, **진행** (의도된 정책) |

패키지 배포 후 7일간은 계보 수집을 건너뛰고 관찰 기간으로 처리한다
(`COOLDOWN_DAYS`, [cooldown.py](src/rootkeepers/interceptor/cooldown.py)).

`UNVERIFIABLE`을 차단하지 않는 건 의도된 설계다. 규칙 엔진은 위험 신호 하나만으로
차단하지 않고 여러 규칙이 동시에 RISK 밴드에 걸려야 차단한다
(`detailed_rule_engine.py`의 `minimum_corroborating_rules`/`minimum_risk_band_rules`).
"증거가 없다"를 "위험하다"와 같은 강도로 차단하면 이 원칙에 어긋나고, 특히 쿨다운은
모든 신규 버전을 배포 후 7일간 설치 불가능하게 만들어 실사용성을 크게 해친다.

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
├── examples/demo-project/                      검사 대상 예제 (기본값)
├── tests/                                      shim 회귀 테스트 · sigstore 수동 점검
├── requirements.txt · pyproject.toml · README.md
│
└── src/rootkeepers/                            ── 파이썬 패키지 전부
    ├── cli.py               `trustgate` 진입점 — 실행·정지·진단
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
    │   ├── safe_npm.py          검사 후 진짜 npm에 위임
    │   ├── reporting.py         대시보드 전송 + 콘솔이 없으면 로컬 기록
    │   ├── inventory.py         설치된 패키지 목록 읽기 (네트워크 없음)
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
