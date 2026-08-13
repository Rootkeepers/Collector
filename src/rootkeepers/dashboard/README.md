# TrustGate 콘솔

npm 패키지를 설치하기 전에 계보(npm·GitHub·Sigstore)를 수집해 6개 공급망 규칙으로 채점하고,
위험하면 설치를 막는 로컬 도구. 스캔·판정·설치·이력 보관을 **서비스 하나**가 담당한다.

## 한 줄 실행

```bash
trustgate up
```
→ http://localhost:8000 · 종료는 `trustgate down`, 진단은 `trustgate doctor`

**필요한 것**: 루트에 `.env` 파일로 `GITHUB_TOKEN=...` (레포에 커밋되지 않음)

---

## 화면

| | 내용 |
|---|---|
| **Dashboard** | 이번 세션 스캔 지표 + 패키지 스캔 실행 |
| **Package Explorer** | 스캔 결과 → 클릭하면 개요·규칙 점수·증거 JSON·리포트 탭 |
| **Installed Packages** | 프로젝트의 설치 버전 vs 최신 버전, 쿨다운 상태, 조기 승인 설치 |
| **History** | 콘솔 스캔 + 터미널(`safe-npm`) 활동이 함께 쌓임. 행을 클릭하면 **그때 어떤 규칙이 왜 그렇게 판단했는지** 펼쳐진다. 재시작해도 남는다 |

---

## 터미널에서 쓰기 (선택)

`npm install` 대신 아래 명령을 쓰면 설치 전에 검사가 걸리고, 결과가 콘솔
History에 쌓인다. 통과하면 진짜 npm에 그대로 위임한다.

```powershell
$env:PYTHONPATH = "C:\...\Collector\src"

python -m rootkeepers.interceptor install axios   # 검사 → 통과 시 실제 설치
python -m rootkeepers.interceptor --trustgate-sync  # 현재 폴더 설치 목록을 콘솔로
```
```bash
export PYTHONPATH="/path/to/Collector/src"
```

`install` 이외의 서브커맨드(`run`, `ci`, `publish` …)는 검사 없이 그대로 npm에 넘어간다.

> `TRUSTGATE_PROJECT_DIR`가 가리키는 폴더는 콘솔이 직접 읽는다. 그 밖의 폴더를
> 화면에 띄우려면 해당 폴더에서 위 `--trustgate-sync` 를 한 번 실행하면 된다.

---

## 환경변수

| 변수 | 기본값 | 용도 |
|---|---|---|
| `GITHUB_TOKEN` | *(필수)* | GitHub 트랙 수집 |
| `TRUSTGATE_PROJECT_DIR` | 저장소의 `examples/demo-project/` | Installed Packages 대상 폴더 |
| `TRUSTGATE_DB_PATH` | `~/.trustgate/history.sqlite3` | 이력 DB |
| `TRUSTGATE_HOST` / `TRUSTGATE_PORT` | `127.0.0.1` / `8000` | 바인드 주소 |
| `TRUSTGATE_RUNTIME_DIR` | `~/.trustgate/` | PID·로그 (`trustgate up`) |
| `TRUSTGATE_BASELINE` | `sigstore` | 기준선 수집 범위 (아래 참고) |
| `TRUSTGATE_CONSOLE_URL` | `http://127.0.0.1:8000` | CLI가 결과를 보낼 주소. 비우면 전송 안 함 |

---

## 기준선(baseline) — 규칙이 "평소와 달라졌다"를 판단하는 근거

6규칙 중 5개는 절대적 나쁨이 아니라 **변화**를 본다. 비교할 과거가 없으면
감점하지 않고 `UNVERIFIABLE`로 남는다(모르는 것을 안전하다고 속이지 않기 위함).

| `TRUSTGATE_BASELINE` | 추가 API 호출 | 풀리는 규칙 |
|---|---|---|
| `off` | 0 | — |
| `npm` | **0회** (패키지 문서에 이미 포함) | `tag_identity_drift`, `unexpected_builder`, `oidc_mismatch` |
| `sigstore` **(기본)** | 릴리스당 1회 | 위 + `workflow_drift` |

실측 (vite@8.2.1, 최근 5개 릴리스): `off` 1/6 → `npm` 3/6 → `sigstore` **4/6** 규칙 평가 가능.

**아직 `UNVERIFIABLE`로 남는 2개** — `orphan_release`(거버넌스 부분), `unreviewed`.
과거 릴리스의 커밋·PR·리뷰어 이력이 필요한데 릴리스당 GitHub API 약 5회가 들어
레이트리밋 소모가 크다. 캐시 설계가 선행되어야 한다.

> `orphan_release`는 기준선 없이도 **gitHead가 GitHub에 존재하는지**라는 절대적 사실은
> 판정한다(2021 ua-parser-js 사고 패턴).

---

## 설계 원칙 (바꾸지 말 것)

**fire-and-forget** — CLI가 콘솔로 보내는 전송은 데몬 스레드에서 일어나고 응답을 기다리지 않는다.
**콘솔이 꺼져 있어도 `npm install` 차단/허용은 100% 그대로 동작해야 한다.**
보안 도구가 가용성 단일 장애점이 되면 안 되기 때문이다.

---

## ⚠️ 보안

이 콘솔은 **인증이 없고 패키지 설치를 실행할 수 있다.** 반드시 `127.0.0.1`에만
노출할 것 (`trustgate up` 기본값이 그렇게 되어 있다). 공개 네트워크에 열면 안 된다.

## 알려진 한계

- 위 2개 규칙의 기준선 미수집
- 기준선 캐시가 없어 같은 패키지를 다시 스캔하면 매번 다시 수집한다
- 여러 PC를 한 화면에 모아 보는 기능은 없다 (PC마다 자기 이력을 본다)
