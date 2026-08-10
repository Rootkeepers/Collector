# TrustGate 로컬 콘솔 (:8000) — 스캔 · 규칙 점수 · 증거 · 설치 게이트 UI.
#
# 이 이미지는 실제 수집기를 돌리므로 의존성이 필요하다:
#   - Python 패키지: PyGithub / requests / python-dotenv / cryptography
#   - npm: "Installed Packages"에서 실제 설치를 실행하기 때문에 Node가 있어야 한다
#
# 컨테이너에서 동작하는 것 / 안 하는 것:
#   ✅ 패키지 스캔(npm·GitHub·Sigstore API) — 순수 네트워크라 그대로 동작
#   ✅ 규칙 점수 · 증거 JSON · 리포트 · Collector Health · 샘플 시나리오
#   ⚠️ Installed Packages / 설치 실행 — 검사할 프로젝트를 **볼륨으로 마운트**해야
#      보인다. 마운트하지 않은 호스트 폴더는 컨테이너에서 보이지 않는다.

FROM python:3.13-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app/src

# Node는 설치 게이트가 실제 npm을 실행하기 위해 필요하다.
RUN apt-get update \
    && apt-get install -y --no-install-recommends nodejs npm \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY src/ /app/src/

# npm을 safe-npm으로 완전히 래핑
# 1. 원본 npm을 npm.real로 저장
# 2. /usr/bin/npm을 safe-npm 래퍼 스크립트로 교체
RUN mv /usr/bin/npm /usr/bin/npm.real && \
    printf '#!/bin/bash\nexec python -m rootkeepers.interceptor.safe_npm "$@"\n' > /usr/bin/npm && \
    chmod +x /usr/bin/npm

# safe-npm이 원본 npm을 찾도록 환경변수 설정
ENV ROOTKEEPERS_REAL_NPM=/usr/bin/npm.real

# 검사 대상 프로젝트를 마운트할 지점
RUN mkdir -p /workspace && \
    echo '{"name":"workspace","version":"1.0.0","dependencies":{}}' > /workspace/package.json

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request,sys; r=urllib.request.urlopen('http://127.0.0.1:8000/api/health',timeout=2); r.read(); r.close(); sys.exit(0 if r.status==200 else 1)"

# 컨테이너 안에서 127.0.0.1에 바인드하면 포트를 매핑해도 밖에서 닿지 않는다.
CMD ["python", "-m", "rootkeepers.dashboard", "--host", "0.0.0.0", "--port", "8000"]
