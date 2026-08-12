<<<<<<< HEAD
# Rootkeepers Collector

npm install을 가로채서, 설치 대상 패키지가 실제로 어디서(GitHub) 어떻게(GitHub Actions/Sigstore) 빌드·배포됐는지 계보를 추적하고 신뢰도를 판정하는 공급망 보안 도구.

npm 레지스트리(Track A) → GitHub 저장소(Track B) → Sigstore/Rekor attestation(Track C) 세 갈래 증거를 모아 하나의 릴리스 계보 리포트로 합치고, 규칙 엔진으로 `PASS`/`RISK`/`UNVERIFIABLE`을 판정한다.

## 요구 사항

- Python 3.10+
- Node.js / npm
- [pipx](https://pipx.pypa.io/) (`sudo apt install pipx` 또는 `brew install pipx`)
- GitHub Personal Access Token (fine-grained, "Public Repositories (read-only)")

## 설치

최신 Debian/Ubuntu는 시스템 Python에 `pip install`을 직접 하는 걸 막아놓는다
(PEP 668, `externally-managed-environment` 에러). `pipx`는 패키지마다 격리된
가상환경을 자동으로 만들어주면서도 커맨드는 평소처럼 PATH에서 바로 쓸 수 있게
해주므로, 이 문제를 피하면서 안전하게 설치할 수 있는 방법이다.

레포 루트(`pyproject.toml`이 있는 위치)에서:

```bash
pipx install -e .
pipx ensurepath
```

`pipx ensurepath` 실행 후 새 터미널을 열면 `safe-npm`, `safe-npm-setup` 두
커맨드가 PATH에서 바로 잡힌다.

## GitHub 토큰 설정

`.env.example`을 참고해 프로젝트 루트에 `.env` 파일을 만든다.

```bash
cp .env.example .env
```

`.env`에 발급받은 토큰을 채워넣는다.

```env
GITHUB_TOKEN=ghp_your_github_token_here
```

`.env`는 `.gitignore`에 포함되어 있어 커밋되지 않는다 — 각자 자기 컴퓨터에 자기 토큰으로 만들어야 한다.

## npm 인터셉트 활성화

```bash
safe-npm-setup
```

`~/.local/bin` 같은 이미 PATH 우선순위인 디렉터리(또는 새로 만든 전용 디렉터리)에 `npm` shim을 설치한다. 이후 `npm install <패키지>`라고만 쳐도 자동으로 검사를 거친 뒤 실제 npm에 위임된다. `install`/`i`가 아닌 다른 npm 서브커맨드(`run`, `ci` 등)는 검사 없이 그대로 통과한다.

새 디렉터리를 만든 경우, 셸 rc 파일(`~/.bashrc`/`~/.zshrc`)에 PATH 설정이 추가되므로 새 터미널을 열거나 `source`해야 적용된다.

제거하려면:

```bash
safe-npm-setup --uninstall
```

shim 없이 직접 검사만 실행하려면:

```bash
safe-npm install <패키지명>
```

## 판정 기준

| 판정 | 의미 | 설치 차단 여부 |
|---|---|---|
| `PASS` | 계보 검증 통과 | 진행 |
| `RISK` | 규칙 위반 탐지 (예: OIDC mismatch) | **차단** |
| `UNVERIFIABLE` | 쿨다운 미경과(배포 7일 이내) 또는 계보 수집 불가 | 경고만 출력, **진행** (의도된 정책) |

패키지 배포 후 7일간은 계보 수집을 건너뛰고 관찰 기간으로 처리한다 (`COOLDOWN_DAYS`, [cooldown.py](src/rootkeepers/interceptor/cooldown.py)).

`UNVERIFIABLE`을 차단하지 않는 건 의도된 설계다. 규칙 엔진은 위험 신호 하나만으로 차단하지 않고 여러 규칙이 동시에 RISK 밴드에 걸려야만 차단하도록 만들어져 있다 (`detailed_rule_engine.py`의 `minimum_corroborating_rules`/`minimum_risk_band_rules`). "증거가 없다"를 "위험하다"와 같은 강도로 차단하면 이 원칙에 어긋나고, 특히 쿨다운은 모든 패키지의 모든 신규 버전을 배포 후 7일간 설치 불가능하게 만들어버려 실사용성을 크게 해친다.

## 프로젝트 구조

```
src/rootkeepers/
├── collectors/
│   ├── npm/         # Track A: npm 레지스트리 메타데이터
│   ├── github/       # Track B: GitHub 커밋/태그/워크플로 증거
│   └── sigstore/      # Track C: Sigstore/Rekor SLSA provenance
└── interceptor/
    ├── safe_npm.py      # npm install 게이트 로직
    ├── cooldown.py       # 배포일 기반 쿨다운 게이트
    ├── detailed_rule_engine.py  # 규칙 엔진
    ├── lineage.py         # Track A/B/C 오케스트레이션
    └── shim_installer.py    # npm shim 설치/제거 (safe-npm-setup)
```

각 collector 하위 폴더의 `README.md`에는 해당 모듈의 상세 개발 기록이 있다.
=======
# TrustGate — npm 공급망 계보 검증 도구

npm 패키지를 설치하기 **전에** 그 릴리스가 어디서 어떻게 만들어졌는지(계보)를
npm·GitHub·Sigstore 세 곳에서 수집하고, 6개 공급망 규칙으로 채점해 위험하면
설치를 막는다.

`event-stream`(2018), `ua-parser-js`(2021) 같은 사고는 전부 평소와 똑같은
`npm install` 한 번으로 성립했다. 그래서 이 도구는 "무엇이 나쁜가"가 아니라
**"평소와 무엇이 달라졌는가"** 를 본다.

```bash
docker compose up -d --build
```
→ http://localhost:8000 · 자세한 사용법은 **[src/rootkeepers/dashboard/README.md](src/rootkeepers/dashboard/README.md)**

---

## 구조

```
Collector/
├── compose.yaml · Dockerfile · .env.example    배포 (서비스 하나)
├── examples/demo-project/                      검사 대상 예제 (기본값)
├── requirements.txt · README.md
│
└── src/rootkeepers/                            ── 파이썬 패키지 전부
    ├── paths.py              저장소 경로 · `.env` 로딩 (세 패키지가 모두 씀)
    │
    ├── collectors/           ── 계보 수집 (Track A/B/C)
    │   ├── npm/                  Track A: 레지스트리 메타데이터, gitHead, 배포자
    │   ├── github/               Track B: 커밋·태그·워크플로 증거
    │   └── sigstore/             Track C: Rekor 투명성 로그, SLSA provenance
    │
    ├── interceptor/          ── 판정 · 설치 게이트 · 터미널 CLI
    │   ├── scanning.py           스캔 진입점 — CLI와 대시보드가 함께 쓴다
    │   ├── detailed_rule_engine.py  6규칙 채점 엔진
    │   ├── baseline.py           과거 릴리스 수집 — "평소"의 기준선
    │   ├── lineage.py            세 트랙을 하나의 계보로 통합
    │   ├── cooldown.py           신버전 관찰 기간(7일) 게이트
    │   ├── safe_npm.py           검사 후 진짜 npm에 위임
    │   ├── reporting.py          CLI → 대시보드 fire-and-forget 전송
    │   ├── inventory.py          설치된 패키지 목록 읽기 (네트워크 없음)
    │   └── __main__.py           CLI 진입점
    │
    └── dashboard/            ── 웹 대시보드 (포트 8000)
        ├── server.py             HTTP API + 정적 서빙
        ├── store.py              이력 SQLite (대시보드 전용)
        ├── __main__.py           `python -m rootkeepers.dashboard`
        ├── README.md             화면·환경변수·기준선 설명
        └── static/               브라우저로 나가는 것만
            ├── console.html · app.css · app.js
            └── fonts/            Inter · JetBrains Mono
```

---

## 두 가지 사용 방식

| | 방법 | 특징 |
|---|---|---|
| **웹 대시보드** | `docker compose up -d` → localhost:8000 | 스캔·판정 근거 열람·설치·이력을 화면에서 |
| **터미널 CLI** | `python -m rootkeepers.interceptor install <pkg>` | 설치 전 검사 후 통과 시 실제 npm에 위임 |

둘은 **같은 판정 엔진**([scanning.py](src/rootkeepers/interceptor/scanning.py))을 쓴다. 같은 패키지에 대해
터미널과 대시보드의 결과가 갈리지 않는다.

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

판정은 **PASS / WARN / RISK / UNVERIFIABLE** 네 밴드로 나온다.
비교할 과거가 없으면 감점하지 않고 `UNVERIFIABLE`로 남긴다 —
**모르는 것을 안전하다고 속이지 않기 위해서다.**

---

## 로컬 실행 (Docker 없이)

```bash
pip install -r requirements.txt
cp .env.example .env          # GITHUB_TOKEN 채우기
export PYTHONPATH=src
python -m rootkeepers.dashboard
```

`.env`의 `GITHUB_TOKEN`은 **절대 커밋되지 않는다**(`.gitignore` 처리).

---

## ⚠️ 보안

콘솔은 **인증이 없고 패키지 설치를 실행할 수 있다.** 반드시 `127.0.0.1`에만
노출할 것 (compose 기본값이 그렇게 되어 있다). 공개 네트워크에 열면 안 된다.
>>>>>>> 3b95edf (feat: Dashboard)
