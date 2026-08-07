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

`src/rootkeepers/collectors/.env.example`을 참고해 프로젝트 루트에 `.env` 파일을 만든다.

```bash
cp src/rootkeepers/collectors/.env.example .env
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
