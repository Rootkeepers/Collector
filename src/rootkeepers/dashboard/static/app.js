// TrustGate 콘솔 — 화면 로직.
// console.html 의 </body> 직전에서 로드되므로 DOM 은 이미 준비되어 있다.

(function () {
  const RULES = ['orphan_release','unreviewed','workflow_drift','oidc_mismatch','unexpected_builder','tag_identity_drift'];
  const RULE_LABEL = { orphan_release: 'Orphan Release', unreviewed: 'Unreviewed', workflow_drift: 'Workflow Drift', oidc_mismatch: 'OIDC Mismatch', unexpected_builder: 'Unexpected Builder', tag_identity_drift: 'Tag/Identity Drift' };
  const WEIGHTS = { orphan_release: 0.7, unreviewed: 0.6, workflow_drift: 0.8, oidc_mismatch: 1.0, unexpected_builder: 0.9, tag_identity_drift: 0.6 };
  const BLOCK_THRESHOLD = 75, MIN_CORROBORATING = 2, MIN_RISK_BAND = 2;

  function cssVar(name) { return getComputedStyle(document.documentElement).getPropertyValue(name).trim(); }
  function escapeHtml(s) { return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;'); }
  function fmtSpec(name, version) { return version ? `${name}@${version}` : `${name} (버전 미확정)`; }
  function safeId(s) { return String(s).replace(/[^a-zA-Z0-9_-]/g, '_'); }
  function isUnverifiable(verdict) { return String(verdict || '').startsWith('UNVERIFIABLE'); }

  let liveResults = [];
  let selected = null;
  let activeRule = null;
  let detailTab = 'overview';

  /* =========================================================
   * Tooltip
   * ========================================================= */
  const tooltip = document.getElementById('tooltip');
  function showTip(evt, title, signals) {
    let body = !signals || !signals.length
      ? '<div class="tt-empty">발동한 세부 신호 없음</div>'
      : signals.map(s => `<div class="tt-sig"><span>${s.id} <span style="color:var(--warning)">+${s.points}</span></span></div><div class="tt-sig"><span class="r">${s.reason}</span></div>`).join('');
    tooltip.innerHTML = `<div class="tt-title">${title}</div><div class="tt-body">${body}</div>`;
    tooltip.style.left = evt.clientX + 'px'; tooltip.style.top = evt.clientY + 'px'; tooltip.style.opacity = '1';
  }
  function moveTip(evt) { tooltip.style.left = evt.clientX + 'px'; tooltip.style.top = evt.clientY + 'px'; }
  function hideTip() { tooltip.style.opacity = '0'; }

  /* =========================================================
   * Sidebar nav / view switching
   * ========================================================= */
  document.querySelectorAll('.nav-item').forEach(btn => {
    btn.addEventListener('click', () => switchView(btn.dataset.view));
  });
  function switchView(view) {
    document.querySelectorAll('.nav-item').forEach(b => b.classList.toggle('active', b.dataset.view === view));
    document.querySelectorAll('.view').forEach(v => v.classList.toggle('active', v.id === 'view-' + view));
    if (view === 'installed' && !installedLoadedOnce) loadInstalled();
    if (view === 'history') loadHistory();
    renderCurrentView();
  }
  function renderCurrentView() {
    renderDetail('explorer-detail-panel');
  }

  /* 경로를 비워 둔 채 설치를 누르면 서버가 쓰는 기본 대상이 전역인지 여부.
   * /api/health 가 알려 준다 — 전역이면 설치 전에 확인을 받는다. */
  let defaultScopeIsGlobal = false;

  /* =========================================================
   * Connection check
   * ========================================================= */
  fetch('/api/health').then(r => r.json()).then(d => {
    defaultScopeIsGlobal = d.default_scope === 'global';
    const pill = document.getElementById('conn-pill'), label = document.getElementById('conn-label');
    if (d.ok && d.github_token_configured) { pill.className = 'status-pill ok'; label.textContent = '서버 연결됨 · TOKEN OK'; }
    else if (d.ok) { pill.className = 'status-pill bad'; label.textContent = 'GITHUB_TOKEN 미설정'; }

  }).catch(() => {
    document.getElementById('conn-pill').className = 'status-pill bad';
    document.getElementById('conn-label').textContent = '서버 미연결';
  });

  /* =========================================================
   * Scan
   * ========================================================= */
  const scanInput = document.getElementById('scan-input');
  const scanBtn = document.getElementById('scan-btn');
  const statusArea = document.getElementById('scan-status-area');

  function parseSpec(spec) {
    spec = spec.trim();
    const scoped = spec.startsWith('@');
    const body = scoped ? spec.slice(1) : spec;
    if (body.includes('@')) { const idx = body.lastIndexOf('@'); return { name: (scoped ? '@' : '') + body.slice(0, idx), version: body.slice(idx + 1) }; }
    return { name: spec, version: null };
  }

  async function runScan(spec) {
    const { name, version } = parseSpec(spec);
    if (!name) return;
    scanBtn.disabled = true;
    const startedAt = Date.now();
    let timer = setInterval(() => {
      const s = ((Date.now() - startedAt) / 1000).toFixed(1);
      statusArea.innerHTML = `<div class="scan-status"><span class="spinner"></span><span>${name}${version ? '@' + version : ''} 스캔 중… ${s}s 경과</span></div>`;
    }, 100);
    try {
      const q = new URLSearchParams({ package: name }); if (version) q.set('version', version);
      const res = await fetch('/api/scan?' + q.toString());
      const data = await res.json();
      clearInterval(timer); statusArea.innerHTML = '';
      if (!data.ok) { statusArea.innerHTML = `<div class="scan-error"><b>스캔 실패</b> — ${escapeHtml(data.error || '알 수 없는 오류')}</div>`; return; }
      const item = normalizeLive(data);
      liveResults.unshift(item);
      selected = item; activeRule = null; detailTab = 'overview';
      renderOverview(); renderExplorer(); renderDashboardRecent();
      renderCurrentView();
    } catch (err) {
      clearInterval(timer);
      statusArea.innerHTML = `<div class="scan-error"><b>서버에 연결할 수 없음</b> — <span class="mono">python webapp/server.py</span> 실행 여부를 확인하라. (${escapeHtml(String(err))})</div>`;
    } finally { scanBtn.disabled = false; }
  }

  function normalizeLive(data) {
    const rules = {};
    (data.rules || []).forEach(r => { rules[r.id] = { score: r.score, band: r.band, reason: r.reason, signals: r.signals || [], evidence_limitations: r.evidence_limitations || [] }; });
    const limited = (data.rules || []).filter(r => r.evidence_limitations && r.evidence_limitations.length);
    let scenario = `실제 스캔 · ${new Date(data.generated_at || Date.now()).toLocaleString('ko-KR')}`;
    if (limited.length === RULES.length) scenario += ' — baseline 이력이 없어 6개 규칙 모두 비교 기준선이 부족하다 (미구현 기능).';
    return {
      id: `live:${data.package.name}@${data.package.version}:${Date.now()}`,
      name: data.package.name, version: data.package.version, source: 'live', scenario, rules,
      decision: { score: data.score, verdict: data.verdict, reason: data.reason, corroboration: data.corroboration.bonus, activatedCount: data.corroboration.activated_rule_count, riskBandCount: data.corroboration.risk_band_rule_count },
      evidenceByRule: data.evidence, trackStatuses: data.track_statuses, timing: data.timing,
      pipeline: data.pipeline, publishedAt: (data.pipeline || []).find(n => n.id === 'resolve_version')?.detail?.published_at || null,
      cooldown: (() => {
        const node = (data.pipeline || []).find(n => n.id === 'cooldown');
        return node ? { passed: node.status === 'PASS', ...node.detail } : null;
      })(),
    };
  }

  /* 이력(SQLite)에 남은 판정을 화면이 쓰는 모양으로 되살린다.
   * DB에는 verdict/score/rules/track_statuses/timing만 저장돼 있어, 증거
   * 원문과 파이프라인은 복원되지 않는다 — 해당 탭은 비어 보인다. */
  function normalizeStored(ev) {
    const rules = {};
    (ev.rules || []).forEach(r => {
      rules[r.id] = { score: r.score, band: r.band, reason: r.reason, signals: r.signals || [], evidence_limitations: r.evidence_limitations || [] };
    });
    return {
      id: `db:${ev.id}`,
      name: ev.package_name, version: ev.package_version, source: 'stored',
      scenario: `${ev.source || 'console'} · ${ev.event} · ${new Date(ev.created_at).toLocaleString('ko-KR')}`,
      rules,
      decision: { score: ev.score ?? 0, verdict: ev.verdict, reason: ev.reason, corroboration: 0, activatedCount: 0, riskBandCount: 0 },
      evidenceByRule: {}, trackStatuses: ev.track_statuses || {}, timing: ev.timing || null,
      pipeline: [], publishedAt: null, cooldown: null,
    };
  }

  async function loadStoredScans() {
    try {
      const res = await fetch('/api/scans');
      const data = await res.json();
      if (!data.ok) return;
      // 같은 패키지를 이번 세션에 다시 스캔했다면 그 결과(LIVE)를 우선한다.
      const liveNames = new Set(liveResults.map(p => p.name));
      const stored = data.scans.filter(ev => !liveNames.has(ev.package_name)).map(normalizeStored);
      if (!stored.length) return;
      liveResults.push(...stored);
      renderOverview(); renderExplorer(); renderCurrentView();
    } catch { /* 이력이 없어도 화면은 그대로 동작한다 */ }
  }

  scanBtn.addEventListener('click', () => runScan(scanInput.value));
  scanInput.addEventListener('keydown', (e) => { if (e.key === 'Enter') runScan(scanInput.value); });
  document.getElementById('quick-lodash').addEventListener('click', () => { scanInput.value = 'lodash'; runScan('lodash'); });
  document.getElementById('quick-react').addEventListener('click', () => { scanInput.value = 'react'; runScan('react'); });
  document.getElementById('quick-leftpad').addEventListener('click', () => { scanInput.value = 'left-pad'; runScan('left-pad'); });

  /* global search filters explorer table */
  document.getElementById('global-search').addEventListener('input', (e) => {
    switchView('explorer');
    renderExplorer(e.target.value.trim().toLowerCase());
  });

  /* =========================================================
   * Overview cards + sparkline
   * ========================================================= */
  function sparklinePath(values, w, h) {
    if (values.length < 2) return '';
    const max = Math.max(...values, 1), min = Math.min(...values, 0);
    const range = max - min || 1;
    return values.map((v, i) => {
      const x = (i / (values.length - 1)) * w;
      const y = h - ((v - min) / range) * h;
      return `${i === 0 ? 'M' : 'L'}${x.toFixed(1)},${y.toFixed(1)}`;
    }).join(' ');
  }
  function sparkSvg(values, color) {
    const w = 100, h = 26;
    if (values.length < 2) return `<svg class="spark" viewBox="0 0 ${w} ${h}"><line x1="0" y1="${h-1}" x2="${w}" y2="${h-1}" stroke="var(--border)" /></svg>`;
    const d = sparklinePath(values, w, h);
    return `<svg class="spark" viewBox="0 0 ${w} ${h}" preserveAspectRatio="none"><path d="${d}" fill="none" stroke="${color}" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" /></svg>`;
  }

  function renderOverview() {
    const total = liveResults.length;
    const allowed = liveResults.filter(p => p.decision.verdict === 'PASS').length;
    const blocked = liveResults.filter(p => p.decision.verdict === 'RISK').length;
    const unverifiable = liveResults.filter(p => isUnverifiable(p.decision.verdict)).length;
    // 이력에서 되살린 행은 소요 시간이 없을 수 있다. 그대로 평균에 넣으면
    // NaN이 되어 스파크라인 path가 깨지므로, 측정값이 있는 것만 집계한다.
    const timed = liveResults.filter(p => p.timing && Number.isFinite(p.timing.total));
    const avgOf = (key) => timed.length
      ? Math.round(timed.reduce((s, p) => s + p.timing[key], 0) / timed.length) : 0;
    const avgMs = avgOf('total');
    const avgGithub = avgOf('github');
    const totalHist = timed.slice(0, 12).map(p => p.timing.total).reverse();
    const githubHist = timed.slice(0, 12).map(p => p.timing.github).reverse();
    const scoreHist = liveResults.slice(0, 12).map(p => p.decision.score).reverse();

    const cards = [
      { label: 'Packages Analyzed', value: total, cls: '' , spark: null },
      { label: 'Allowed', value: allowed, cls: 'good', spark: null },
      { label: 'Blocked', value: blocked, cls: blocked ? 'critical' : '', spark: sparkSvg(scoreHist, cssVar('--critical')) },
      { label: 'Unverifiable', value: unverifiable, cls: 'warning', spark: null },
      { label: 'Avg Analysis Time', value: avgMs ? avgMs + 'ms' : '—', cls: '', spark: sparkSvg(totalHist, cssVar('--accent')) },
      { label: 'GitHub Latency', value: avgGithub ? avgGithub + 'ms' : '—', cls: '', spark: sparkSvg(githubHist, cssVar('--purple')) },
    ];
    document.getElementById('overview-cards').innerHTML = cards.map(c => `
      <div class="stat-card">
        <div class="label">${c.label}</div>
        <div class="value mono ${c.cls}">${c.value}</div>
        ${c.spark || ''}
      </div>
    `).join('');
  }

  function renderDashboardRecent() {
    const area = document.getElementById('dashboard-recent');
    if (!liveResults.length) { area.innerHTML = '<div class="no-selection">아직 스캔 기록이 없다.</div>'; return; }
    const p = liveResults[0];
    area.innerHTML = `
      <div class="pkg-header"><span class="title">${fmtSpec(p.name, p.version)}</span><span class="verdict-pill ${p.decision.verdict}">${p.decision.verdict} · ${p.decision.score}/100</span></div>
      <p class="pkg-scenario">${p.scenario}</p>
      <div class="track-chips">${Object.entries(p.trackStatuses).map(([k,v]) => `<span class="track-chip ${v}">${k}: ${v}</span>`).join('')}</div>
    `;
  }

  /* =========================================================
   * Package Explorer
   * ========================================================= */
  function renderExplorer(filter) {
    filter = (filter || '').toLowerCase();
    const tbody = document.getElementById('explorer-tbody');
    const empty = document.getElementById('explorer-empty');
    const rows = liveResults.filter(p => !filter || p.name.toLowerCase().includes(filter) || (p.version||'').toLowerCase().includes(filter));
    empty.style.display = liveResults.length ? 'none' : 'block';
    tbody.innerHTML = rows.map(p => `
      <tr data-id="${p.id}" class="${selected && selected.id === p.id ? 'active' : ''}">
        <td class="pkg-name-cell">${p.name}${p.source === 'stored' ? '<span class="src-tag stored">기록</span>' : '<span class="src-tag live">LIVE</span>'}</td>
        <td class="mono">${p.version || '—'}</td>
        <td class="mono">${p.publishedAt ? new Date(p.publishedAt).toLocaleDateString('ko-KR') : '—'}</td>
        <td class="mono">${p.decision.score}</td>
        <td><span class="verdict-pill ${p.decision.verdict}">${p.decision.verdict}</span></td>
        <td>${Object.entries(p.trackStatuses).map(([k,v]) => `<span class="track-dot ${v}" title="${k}: ${v}"></span>`).join('')}</td>
      </tr>
    `).join('');
    tbody.querySelectorAll('tr').forEach(tr => {
      tr.addEventListener('click', () => {
        const clicked = liveResults.find(p => p.id === tr.dataset.id);
        if (selected && selected.id === clicked.id) return; // keep current tab on re-click
        selected = clicked;
        activeRule = null; detailTab = 'overview';
        renderExplorer(filter); renderCurrentView();
      });
    });
    renderDetail('explorer-detail-panel');
  }

  function riskGaugeSvg(score, verdict) {
    const r = 42, c = 2 * Math.PI * r;
    const color = verdict === 'RISK' ? 'var(--critical)' : isUnverifiable(verdict) ? 'var(--neutral)' : score > 0 ? 'var(--warning)' : 'var(--good)';
    const offset = c * (1 - score / 100);
    return `
      <svg width="104" height="104" viewBox="0 0 104 104">
        <circle cx="52" cy="52" r="${r}" fill="none" stroke="var(--surface-3)" stroke-width="9" />
        <circle cx="52" cy="52" r="${r}" fill="none" stroke="${color}" stroke-width="9" stroke-linecap="round"
          stroke-dasharray="${c}" stroke-dashoffset="${offset}" transform="rotate(-90 52 52)" style="transition: stroke-dashoffset 0.5s ease" />
        <text x="52" y="49" text-anchor="middle" font-family="JBM, monospace" font-weight="800" font-size="22" fill="var(--ink)">${score}</text>
        <text x="52" y="66" text-anchor="middle" font-family="JBM, monospace" font-size="10" fill="var(--muted)">/ 100</text>
      </svg>`;
  }

  /* =========================================================
   * Package detail — one tabbed panel holding everything about the
   * selected package (개요 / 규칙 / 증거 / 리포트). Rendered under
   * whichever table the user clicked from, so reviewing one package
   * never requires jumping around the sidebar.
   * ========================================================= */
  const DETAIL_TABS = [
    { id: 'overview', label: '개요' },
    { id: 'rules', label: '규칙 점수' },
    { id: 'evidence', label: '증거 JSON' },
    { id: 'report', label: '리포트' },
    { id: 'ai', label: 'AI 분석' },
  ];

  /* 패키지별 LangGraph 분석 상태. 탭을 오가도 결과가 날아가지 않게 보관한다. */
  const aiSummaries = {};
  const aiKey = (p) => `${p.name}@${p.version || ''}`;

  async function requestAiSummary(p, containerId) {
    const key = aiKey(p);
    aiSummaries[key] = { status: 'loading' };
    renderDetail(containerId);
    try {
      const res = await fetch('/api/ai-analysis', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json; charset=utf-8' },
        body: JSON.stringify({
          package: { name: p.name, version: p.version },
          verdict: p.decision.verdict, score: p.decision.score, reason: p.decision.reason,
          rules: Object.entries(p.rules).map(([id, rule]) => ({ id, ...rule })),
          track_statuses: p.trackStatuses,
        }),
      });
      // 서버에 아직 엔드포인트가 없는 경우와 실제 오류를 구분한다.
      if (res.status === 404 || res.status === 501) {
        aiSummaries[key] = { status: 'unavailable' };
      } else {
        const data = await res.json();
        aiSummaries[key] = (data.ok && data.analysis)
          ? { status: 'done', data: data.analysis }
          : { status: 'error', error: data.error || '요약을 받지 못했습니다.' };
      }
    } catch (err) {
      aiSummaries[key] = { status: 'error', error: String(err) };
    }
    renderDetail(containerId);
  }

  function renderAiTab(body, p, containerId) {
    const state = aiSummaries[aiKey(p)] || { status: 'idle' };

    let panel;
    if (state.status === 'loading') {
      panel = `<div class="ai-status"><span class="spinner"></span><span>요약을 생성하는 중…</span></div>`;
    } else if (state.status === 'done') {
      const a = state.data;
      const explanation = a.explanation || a.llm || {};
      const summary = explanation.status === 'AVAILABLE' ? explanation.summary : (a.synthesis || {}).summary;
      const headline = explanation.status === 'AVAILABLE' ? explanation.headline : (a.synthesis || {}).headline;
      const monitoring = a.monitoring || {};
      const osv = a.vulnerabilities || {};
      const sast = a.sast || {};
      const actions = explanation.status === 'AVAILABLE' ? explanation.recommended_actions : (a.synthesis || {}).recommended_actions;
      const vulns = (osv.vulnerabilities || []).slice(0, 8).map(v => `
        <li><b>${escapeHtml(v.id || 'OSV')}</b> · ${escapeHtml(v.severity || 'UNKNOWN')}<br>
        <span>${escapeHtml(v.summary || '')}</span>
        ${v.fixed_versions?.length ? `<div class="mono muted">fixed: ${escapeHtml(v.fixed_versions.join(', '))}</div>` : ''}</li>`).join('');
      const sastRows = (sast.findings || []).slice(0, 12).map(f => `
        <li><b>${escapeHtml(f.rule_id || 'SAST')}</b> · ${escapeHtml(f.severity || 'INFO')}
        <div class="mono muted">${escapeHtml(f.path || '')}${f.line ? ':' + f.line : ''}</div>
        <span>${escapeHtml(f.message || '')}</span></li>`).join('');
      panel = `
        <div class="ai-summary"><b>${escapeHtml(headline || '보조 분석')}</b><br>${escapeHtml(summary || '').replace(/\n/g, '<br>')}</div>
        <div class="ai-grid">
          <section class="ai-card"><h4>변화 모니터링 <span class="analysis-badge ${monitoring.status || ''}">${escapeHtml(monitoring.status || 'UNKNOWN')}</span></h4>
            <p>${escapeHtml(monitoring.message || '')}</p>
            ${monitoring.score_delta != null ? `<p class="mono">score delta: ${monitoring.score_delta > 0 ? '+' : ''}${monitoring.score_delta}</p>` : ''}
            ${monitoring.anomaly_score != null ? `<p class="mono">local anomaly: ${monitoring.anomaly_score}/100</p>` : ''}
          </section>
          <section class="ai-card"><h4>OSV 취약 버전 <span class="analysis-badge ${osv.status || ''}">${escapeHtml(osv.status || 'UNKNOWN')}</span></h4>
            <p>${osv.recommended_version ? `권장 수정 버전: <b class="mono">${escapeHtml(osv.recommended_version)}</b>` : escapeHtml(osv.action || '')}</p>
            ${vulns ? `<ul class="analysis-list">${vulns}</ul>` : '<p class="muted">알려진 취약점이 확인되지 않았습니다.</p>'}
          </section>
          <section class="ai-card"><h4>소스/SAST 2차 검증 <span class="analysis-badge ${sast.status || ''}">${escapeHtml(sast.status || 'UNKNOWN')}</span></h4>
            <p>npm 무결성: ${escapeHtml(sast.artifact?.integrity?.status || 'UNKNOWN')} · 신호 ${sast.finding_count || 0}건</p>
            ${sastRows ? `<ul class="analysis-list">${sastRows}</ul>` : '<p class="muted">표시할 SAST 신호가 없습니다.</p>'}
          </section>
          <section class="ai-card"><h4>권장 조치</h4>
            <ol class="analysis-list">${(actions || []).map(x => `<li>${escapeHtml(x)}</li>`).join('')}</ol>
            <p class="muted">설명 엔진: ${escapeHtml((explanation.provider || 'none').toUpperCase())} · ${escapeHtml(explanation.status || 'DISABLED')}${explanation.cost ? ' · ' + escapeHtml(explanation.cost) : ''}</p>
            ${explanation.model ? `<p class="mono muted">${escapeHtml(explanation.model)}</p>` : ''}
            ${explanation.fallback_from ? `<p class="muted">${escapeHtml(explanation.fallback_from.toUpperCase())} API 폴백: ${escapeHtml(explanation.fallback_reason || 'unavailable')}</p>` : ''}
          </section>
        </div>`;
    } else if (state.status === 'unavailable') {
        panel = `<div class="ai-empty">이 서버에는 통합 분석 기능이 연결되지 않았습니다.
               <span class="mono">POST /api/ai-analysis</span> 엔드포인트를 확인하세요.</div>`;
    } else if (state.status === 'error') {
      panel = `<div class="scan-error"><b>요약 실패</b> — ${escapeHtml(state.error)}</div>`;
    } else {
      panel = `<div class="ai-empty">아직 생성된 요약이 없습니다.</div>`;
    }

    body.innerHTML = `
      <p class="subhead">LangGraph가 이력·OSV·Semgrep을 수집하고 무료 Groq API가 설명한다. 키·한도 문제가 있으면 로컬 증거 추론으로 자동 전환한다.</p>
      <div class="scan-form">
        <button class="btn primary" id="ai-run" ${state.status === 'loading' ? 'disabled' : ''}>
          ${state.status === 'done' ? '다시 분석' : '통합 분석 실행'}
        </button>
      </div>
      ${panel}
      <p class="ai-caveat">AI/SAST/OSV 결과는 참고용이다. 설치 여부를 가르는 근거는
        <b>규칙 점수</b>와 <b>증거 JSON</b> 탭의 원본 값이다.</p>
    `;
    body.querySelector('#ai-run').addEventListener('click', () => requestAiSummary(p, containerId));
  }

  function renderDetail(containerId) {
    const panel = document.getElementById(containerId);
    if (!panel) return;
    if (!selected) { panel.innerHTML = ''; return; }
    const p = selected;
    if (!activeRule || (activeRule !== 'package' && !p.rules[activeRule])) {
      const withSignal = RULES.find(r => p.rules[r] && p.rules[r].signals && p.rules[r].signals.length);
      activeRule = withSignal || 'orphan_release';
    }

    panel.innerHTML = `
      <div class="panel">
        <div class="pkg-header">
          <span class="title">${fmtSpec(p.name, p.version)}</span>
          <span style="display:flex; align-items:center; gap:10px;">
            ${p.source === 'stored' ? '<span class="src-tag stored">기록</span>' : '<span class="src-tag live">LIVE</span>'}
            <span class="verdict-pill ${p.decision.verdict}">${p.decision.verdict} · ${p.decision.score}/100</span>
          </span>
        </div>
        <div class="detail-tabs">
          ${DETAIL_TABS.map(t => `<button class="detail-tab ${t.id === detailTab ? 'active' : ''}" data-tab="${t.id}">${t.label}</button>`).join('')}
        </div>
        <div class="detail-tab-body" id="detail-tab-body"></div>
      </div>
    `;
    panel.querySelectorAll('.detail-tab').forEach(btn => {
      btn.addEventListener('click', () => { detailTab = btn.dataset.tab; renderDetail(containerId); });
    });

    const body = panel.querySelector('#detail-tab-body');
    if (detailTab === 'overview') renderOverviewTab(body, p);
    else if (detailTab === 'rules') renderRulesTab(body, p, containerId);
    else if (detailTab === 'evidence') renderEvidenceTab(body, p);
    else if (detailTab === 'ai') renderAiTab(body, p, containerId);
    else renderReportTab(body, p);
  }

  function renderOverviewTab(body, p) {
    body.innerHTML = `
      <div class="grid-2">
        <div>
          <p class="pkg-scenario" style="margin-top:0;">${p.scenario}</p>
          <div style="font-size:12.5px; color:var(--ink-2); line-height:1.65; margin-top:12px;">${p.decision.reason}</div>
          ${p.trackStatuses ? `<div class="track-chips">${Object.entries(p.trackStatuses).map(([k,v]) => `<span class="track-chip ${v}">${k}: ${v}</span>`).join('')}</div>` : ''}
          ${p.cooldown ? `<div class="track-chips"><span class="cooldown-badge ${p.cooldown.passed ? 'passed' : 'holding'}">${p.cooldown.passed ? '쿨다운 통과' : `쿨다운 중 · ${p.cooldown.remain_days != null ? p.cooldown.remain_days.toFixed(1) : '?'}일 남음`}</span></div>` : ''}
          ${p.timing && Number.isFinite(p.timing.total) ? `<div class="track-chips"><span class="track-chip">총 소요 ${p.timing.total}ms</span><span class="track-chip">npm ${p.timing.npm}ms</span><span class="track-chip">github ${p.timing.github}ms</span><span class="track-chip">sigstore ${p.timing.sigstore}ms</span></div>` : ''}
        </div>
        <div class="gauge-wrap">${riskGaugeSvg(p.decision.score, p.decision.verdict)}<div><div class="verdict-pill ${p.decision.verdict}">${p.decision.verdict}</div><div class="gauge-label">보고 기준 ${BLOCK_THRESHOLD} · 실제 게이트 fail-closed</div></div></div>
      </div>
    `;
  }

  /* =========================================================
   * Detection Rules — radar + bars
   * ========================================================= */
  function radarSvg(p) {
    const W = 280, H = 280, cx = W/2, cy = H/2, R = 100;
    const n = RULES.length;
    const bandColor = { PASS: cssVar('--good'), WARN: cssVar('--warning'), RISK: cssVar('--critical'), UNVERIFIABLE: cssVar('--neutral') };
    const points = RULES.map((r, i) => {
      const angle = -Math.PI/2 + i * (2*Math.PI/n);
      const val = p.rules[r].score / 100;
      const x = cx + Math.cos(angle) * R * val;
      const y = cy + Math.sin(angle) * R * val;
      return { x, y, angle, r };
    });
    const poly = points.map(pt => `${pt.x.toFixed(1)},${pt.y.toFixed(1)}`).join(' ');
    const rings = [0.25, 0.5, 0.75, 1].map(f => {
      const ringPts = RULES.map((r,i) => { const a=-Math.PI/2+i*(2*Math.PI/n); return `${(cx+Math.cos(a)*R*f).toFixed(1)},${(cy+Math.sin(a)*R*f).toFixed(1)}`; }).join(' ');
      return `<polygon points="${ringPts}" fill="none" stroke="var(--border)" stroke-width="1" />`;
    }).join('');
    const spokes = RULES.map((r,i) => { const a=-Math.PI/2+i*(2*Math.PI/n); const x=cx+Math.cos(a)*R, y=cy+Math.sin(a)*R; return `<line x1="${cx}" y1="${cy}" x2="${x.toFixed(1)}" y2="${y.toFixed(1)}" stroke="var(--border)" stroke-width="1" />`; }).join('');
    const labels = RULES.map((r,i) => {
      const a=-Math.PI/2+i*(2*Math.PI/n); const lx=cx+Math.cos(a)*(R+34), ly=cy+Math.sin(a)*(R+34);
      return `<text x="${lx.toFixed(1)}" y="${ly.toFixed(1)}" text-anchor="middle" dominant-baseline="middle" font-size="10.5" font-family="JBM, monospace" fill="var(--ink-2)">${RULE_LABEL[r]}</text>`;
    }).join('');
    const dots = points.map((pt,i) => `<circle cx="${pt.x.toFixed(1)}" cy="${pt.y.toFixed(1)}" r="4" fill="${bandColor[p.rules[RULES[i]].band]}" stroke="var(--surface)" stroke-width="1.5" />`).join('');
    return `<svg viewBox="0 0 ${W} ${H}" width="100%" style="max-width:320px">${rings}${spokes}<polygon points="${poly}" fill="var(--accent)" fill-opacity="0.16" stroke="var(--cyan)" stroke-width="2" />${dots}${labels}</svg>`;
  }

  function renderRulesTab(body, p, containerId) {
    body.innerHTML = `
      <div class="grid-2" style="align-items:center;">
        <div style="display:flex; justify-content:center;">${radarSvg(p)}</div>
        <div id="rule-rows"></div>
      </div>
      <div class="verdict-math">
        <span>가중 합산 + 동시발동 보너스 = <b id="vm-score"></b></span>
        <span>동시발동 규칙 <b>${p.decision.activatedCount}</b>개 (최소 ${MIN_CORROBORATING})</span>
        <span>RISK 밴드 <b>${p.decision.riskBandCount}</b>개 (최소 ${MIN_RISK_BAND})</span>
      </div>
      <div style="font-size:12px; color:var(--muted); margin-top:10px;">규칙 막대에 마우스를 올리면 세부 신호가, 클릭하면 '증거 JSON' 탭에서 그 규칙이 선택된다.</div>
    `;
    const ruleRows = body.querySelector('#rule-rows');
    RULES.forEach(r => {
      const rule = p.rules[r] || { score: 0, band: 'UNVERIFIABLE', reason: '데이터 없음', signals: [] };
      const row = document.createElement('div');
      row.className = 'rule-row';
      const trackInner = rule.band === 'UNVERIFIABLE' ? `<span class="unverif-tag">평가 불가 — 기준선/증거 없음</span>` : `<div class="rule-fill ${rule.band}" style="width:${rule.score}%"></div>`;
      row.innerHTML = `
        <span class="rule-name">${RULE_LABEL[r]}<span class="w">가중치 ×${WEIGHTS[r].toFixed(1)}</span></span>
        <div class="rule-track ${r === activeRule ? 'selected' : ''}" data-rule="${r}">${trackInner}</div>
        <span class="rule-score mono">${rule.band === 'UNVERIFIABLE' ? '—' : rule.score}</span>
        <span class="rule-band-tag ${rule.band}">${rule.band}</span>
      `;
      const track = row.querySelector('.rule-track');
      track.addEventListener('mouseenter', (e) => showTip(e, RULE_LABEL[r], rule.signals));
      track.addEventListener('mousemove', moveTip);
      track.addEventListener('mouseleave', hideTip);
      track.addEventListener('click', () => { activeRule = r; detailTab = 'evidence'; hideTip(); renderDetail(containerId); });
      ruleRows.appendChild(row);
    });
    body.querySelector('#vm-score').textContent = `${Math.round(RULES.reduce((s, r) => s + (p.rules[r]?p.rules[r].score:0) * WEIGHTS[r], 0))} + ${p.decision.corroboration} = ${p.decision.score}`;
  }

  /* =========================================================
   * JSON Inspector
   * ========================================================= */
  function jsonHighlight(obj, searchTerm) {
    let json = JSON.stringify(obj, null, 2);
    json = json
      .replace(/"([^"]+)":/g, '<span class="k">"$1"</span>:')
      .replace(/: "([^"]*)"/g, ': <span class="s">"$1"</span>')
      .replace(/: (true|false|null)/g, ': <span class="b">$1</span>')
      .replace(/: (-?\d+(\.\d+)?)/g, ': <span class="n">$1</span>');
    if (searchTerm) {
      const re = new RegExp('(' + searchTerm.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + ')', 'gi');
      json = json.replace(re, '<mark>$1</mark>');
    }
    return json;
  }

  function renderEvidenceTab(body, p) {
    const keys = ['package', ...RULES];
    body.innerHTML = `
      <div class="inspector-wrap">
        <div class="tree-panel" id="tree-panel"></div>
        <div class="json-view-wrap">
          <div class="json-toolbar"><input type="text" id="json-search" placeholder="증거 필드 검색…"><button class="btn" id="json-copy">복사</button></div>
          <div class="json-view mono" id="inspector-json"></div>
        </div>
      </div>
    `;
    const treePanel = body.querySelector('#tree-panel');
    keys.forEach(k => {
      const item = document.createElement('div');
      item.className = 'tree-item' + (k === activeRule ? ' active' : '');
      item.dataset.key = k;
      item.textContent = k === 'package' ? '📦 package' : RULE_LABEL[k];
      item.addEventListener('click', () => {
        activeRule = k;
        treePanel.querySelectorAll('.tree-item').forEach(el => el.classList.toggle('active', el.dataset.key === k));
        refreshJson();
      });
      treePanel.appendChild(item);
    });

    function currentData() {
      return activeRule === 'package'
        ? { name: p.name, version: p.version }
        : (p.evidenceByRule && p.evidenceByRule[activeRule]) || { note: '이 규칙에 대한 증거 필드가 없다.' };
    }
    function refreshJson() {
      body.querySelector('#inspector-json').innerHTML = jsonHighlight(currentData(), body.querySelector('#json-search').value.trim());
    }
    body.querySelector('#json-search').addEventListener('input', refreshJson);
    body.querySelector('#json-copy').addEventListener('click', () => {
      navigator.clipboard && navigator.clipboard.writeText(JSON.stringify(currentData(), null, 2)).catch(()=>{});
    });
    refreshJson();
  }

  /* =========================================================
   * Reports
   * ========================================================= */
  function buildMarkdown(p) {
    const lines = [];
    lines.push(`# TrustGate 분석 리포트 — ${fmtSpec(p.name, p.version)}`);
    lines.push('');
    lines.push(`**출처:** 실제 스캔 (로컬 서버)`);
    lines.push(`**판정:** ${p.decision.verdict}  |  **점수:** ${p.decision.score}/100`);
    lines.push('');
    lines.push(`**근거:** ${p.decision.reason}`);
    lines.push('');
    lines.push(`> ${p.scenario}`);
    lines.push('');
    lines.push('## 규칙별 점수');
    lines.push('');
    lines.push('| 규칙 | 가중치 | 점수 | 밴드 | 신호 |');
    lines.push('|---|---|---|---|---|');
    RULES.forEach(r => {
      const rule = p.rules[r] || { score: 0, band: 'UNVERIFIABLE', signals: [] };
      const sig = rule.signals.length ? rule.signals.map(s => `${s.id}(+${s.points})`).join(', ') : '—';
      lines.push(`| ${RULE_LABEL[r]} | ×${WEIGHTS[r].toFixed(1)} | ${rule.band === 'UNVERIFIABLE' ? '—' : rule.score} | ${rule.band} | ${sig} |`);
    });
    lines.push('');
    lines.push('## 상세 신호');
    lines.push('');
    RULES.forEach(r => {
      const rule = p.rules[r];
      if (!rule || !rule.signals.length) return;
      lines.push(`**${RULE_LABEL[r]}**`);
      rule.signals.forEach(s => lines.push(`- \`${s.id}\` (+${s.points}) — ${s.reason}`));
      lines.push('');
    });
    lines.push('---'); lines.push(`Rootkeepers/TrustGate Scan Console에서 생성`);
    return lines.join('\n');
  }

  function renderReportTab(body, p) {
    const md = buildMarkdown(p);
    body.innerHTML = `
      <div class="report-toolbar">
        <span class="copy-flash" id="report-copy-flash">복사됨 ✓</span>
        <button class="btn" id="report-open">에디터로 열기</button>
        <button class="btn" id="report-download">.md 다운로드</button>
        <button class="btn primary" id="report-copy">클립보드에 복사</button>
      </div>
      <textarea class="report-preview mono" id="report-preview" readonly></textarea>
    `;
    body.querySelector('#report-preview').value = md;
    body.querySelector('#report-copy').addEventListener('click', () => {
      navigator.clipboard && navigator.clipboard.writeText(md).catch(()=>{});
      const f = body.querySelector('#report-copy-flash'); f.classList.add('show'); setTimeout(() => f.classList.remove('show'), 1400);
    });
    body.querySelector('#report-download').addEventListener('click', () => {
      const blob = new Blob([md], { type: 'text/markdown' }); const url = URL.createObjectURL(blob);
      const a = document.createElement('a'); a.href = url; a.download = `trustgate-${p.name}-${p.version || 'unresolved'}.md`;
      document.body.appendChild(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(url), 2000);
    });
    body.querySelector('#report-open').addEventListener('click', () => {
      const blob = new Blob([md], { type: 'text/markdown' }); const url = URL.createObjectURL(blob);
      window.open(url, '_blank');
    });
  }

  /* =========================================================
   * Collector Health
   * ========================================================= */
  /* =========================================================
   * History — 저장된 이력 (콘솔 스캔 + 터미널 safe-npm 활동)
   * ========================================================= */
  let histTimer = null;
  let histExpanded = null;

  function histFilterParams() {
    const p = new URLSearchParams({ limit: '100' });
    const q = document.getElementById('h-q').value.trim();
    const ev = document.getElementById('h-event').value;
    const vd = document.getElementById('h-verdict').value;
    if (q) p.set('q', q);
    if (ev) p.set('event', ev);
    if (vd) p.set('verdict', vd);
    return p;
  }

  async function loadHistory() {
    try {
      const res = await fetch('/api/history?' + histFilterParams().toString());
      const d = await res.json();
      renderHistCards(d.stats);
      renderHistTrend(d.days);
      renderHistTable(d.events);
    } catch (err) {
      document.getElementById('hist-empty').style.display = 'block';
      document.getElementById('hist-empty').textContent = '이력을 불러오지 못했다: ' + err;
    }
  }

  function renderHistCards(s) {
    const cards = [
      { label: 'Total Events', value: s.total_events, sub: `스캔 ${s.scans}건` },
      { label: 'Blocked', value: s.blocked, cls: s.blocked ? 'critical' : '',
        alert: s.blocked > 0, sub: s.blocked ? '확인 필요' : '차단 없음' },
      { label: 'Installed', value: s.installed, cls: 'good' },
      // 평균 점수 대신 '검증 가능 비율' — baseline 이 없으면 규칙이 UNVERIFIABLE로
      // 남으므로, 이 도구가 지금 무엇을 못 보고 있는지를 정직하게 드러낸다.
      { label: 'Verifiable', value: s.verifiable_rate != null ? s.verifiable_rate + '%' : '—',
        sub: `최근 24시간 ${s.last_24h}건` },
    ];
    document.getElementById('hist-cards').innerHTML = cards.map(c => `
      <div class="stat-card${c.alert ? ' alert' : ''}">
        <div class="label">${c.label}</div>
        <div class="value mono ${c.cls || ''}">${c.value}</div>
        ${c.sub ? `<div class="sub">${c.sub}</div>` : ''}
      </div>`).join('');
  }

  function renderHistTrend(days) {
    const W = 520, H = 120, PAD_L = 26, PAD_B = 18, PAD_T = 8;
    const plotW = W - PAD_L - 6, plotH = H - PAD_B - PAD_T;
    const max = Math.max(1, ...days.map(d => d.scans + d.blocks + d.installs));
    const slot = plotW / days.length, barW = Math.min(22, slot * 0.6);
    const series = [
      { key: 'scans', color: 'var(--accent)' },
      { key: 'installs', color: 'var(--good)' },
      { key: 'blocks', color: 'var(--critical)' },
    ];
    let bars = '', labels = '';
    days.forEach((d, i) => {
      const cx = PAD_L + slot * i + slot / 2;
      let y = PAD_T + plotH;
      series.forEach(s => {
        const v = d[s.key];
        if (!v) return;
        const h = (v / max) * plotH; y -= h;
        bars += `<rect x="${(cx - barW/2).toFixed(1)}" y="${y.toFixed(1)}" width="${barW.toFixed(1)}" height="${h.toFixed(1)}" fill="${s.color}" rx="2"><title>${d.day} ${s.key} ${v}</title></rect>`;
      });
      if (i % 2 === 0 || i === days.length - 1) {
        labels += `<text x="${cx.toFixed(1)}" y="${H-5}" text-anchor="middle" font-size="9" font-family="JBM, monospace" fill="var(--muted)">${d.day.slice(5)}</text>`;
      }
    });
    const grid = [0, 0.5, 1].map(f => {
      const y = PAD_T + plotH - f * plotH;
      return `<line x1="${PAD_L}" y1="${y}" x2="${W-6}" y2="${y}" stroke="var(--border)" stroke-width="1"/>`
           + `<text x="${PAD_L-5}" y="${y+3}" text-anchor="end" font-size="9" font-family="JBM, monospace" fill="var(--muted)">${Math.round(max*f)}</text>`;
    }).join('');
    document.getElementById('hist-trend').innerHTML =
      `<svg class="trend-svg" viewBox="0 0 ${W} ${H}" preserveAspectRatio="none">${grid}${bars}${labels}</svg>`;
    const t = days.reduce((a,d)=>({s:a.s+d.scans,i:a.i+d.installs,b:a.b+d.blocks}),{s:0,i:0,b:0});
    document.getElementById('hist-trend-legend').innerHTML =
      `<span><span class="sw" style="background:var(--accent)"></span>scan ${t.s}</span>
       <span><span class="sw" style="background:var(--good)"></span>install ${t.i}</span>
       <span><span class="sw" style="background:var(--critical)"></span>block ${t.b}</span>`;
  }

  function renderHistTable(events) {
    const tbody = document.getElementById('hist-tbody');
    document.getElementById('hist-empty').style.display = events.length ? 'none' : 'block';
    document.getElementById('h-count').textContent = events.length >= 100 ? '최근 100건' : `${events.length}건`;

    tbody.innerHTML = events.map(e => {
      const open = histExpanded === e.id;
      const row = `
        <tr data-id="${e.id}">
          <td class="mono">${escapeHtml(new Date(e.created_at).toLocaleString('ko-KR'))}</td>
          <td><span class="event-tag">${escapeHtml(e.source || '—')}</span></td>
          <td><span class="event-tag">${escapeHtml(e.event)}</span></td>
          <td class="mono">${escapeHtml(e.package_name || '—')}${e.package_version ? '@' + escapeHtml(e.package_version) : ''}</td>
          <td>${e.verdict ? `<span class="verdict-pill ${escapeHtml(e.verdict)}">${escapeHtml(e.verdict)}</span>` : '—'}</td>
          <td class="mono">${e.score != null ? escapeHtml(e.score) : '—'}</td>
          <td class="pkg-chevron">${open ? '▾' : '▸'}</td>
        </tr>`;
      return open ? row + histDetailRow(e) : row;
    }).join('');

    tbody.querySelectorAll('tr[data-id]').forEach(tr => {
      tr.addEventListener('click', () => {
        const id = Number(tr.dataset.id);
        histExpanded = histExpanded === id ? null : id;
        renderHistTable(events);
      });
    });
  }

  function histDetailRow(e) {
    const rules = e.rules || [];
    const bars = rules.map(r => {
      const inner = r.band === 'UNVERIFIABLE'
        ? `<span class="unverif-tag">평가 불가 — 기준선/증거 없음</span>`
        : `<div class="rule-fill ${escapeHtml(r.band)}" style="width:${r.score}%"></div>`;
      const sig = (r.signals || []).map(s => `${escapeHtml(s.id)}(+${s.points})`).join(', ');
      return `
        <div class="rule-row">
          <span class="rule-name">${RULE_LABEL[r.id] || escapeHtml(r.id)}<span class="w">${sig || escapeHtml(r.reason || '')}</span></span>
          <div class="rule-track">${inner}</div>
          <span class="rule-score mono">${r.band === 'UNVERIFIABLE' ? '—' : r.score}</span>
          <span class="rule-band-tag ${escapeHtml(r.band)}">${escapeHtml(r.band)}</span>
        </div>`;
    }).join('');
    const tracks = e.track_statuses
      ? `<div class="track-chips">${Object.entries(e.track_statuses).map(([k,v]) => `<span class="track-chip ${escapeHtml(v)}">${escapeHtml(k)}: ${escapeHtml(v)}</span>`).join('')}</div>` : '';
    const timing = e.timing && Number.isFinite(e.timing.total) ?`<div class="track-chips"><span class="track-chip">총 ${e.timing.total}ms</span><span class="track-chip">npm ${e.timing.npm}ms</span><span class="track-chip">github ${e.timing.github}ms</span><span class="track-chip">sigstore ${e.timing.sigstore}ms</span></div>` : '';
    return `<tr class="hist-detail"><td colspan="7"><div class="hist-detail-inner">
        <div class="hist-reason">${escapeHtml(e.reason || '')}</div>
        ${bars || '<div class="empty-hint">규칙 정보가 없다.</div>'}
        ${tracks}${timing}
      </div></td></tr>`;
  }

  ['h-q','h-event','h-verdict'].forEach(id => {
    document.getElementById(id).addEventListener(id === 'h-q' ? 'input' : 'change', () => {
      clearTimeout(histTimer);
      histTimer = setTimeout(() => { histExpanded = null; loadHistory(); }, 250);
    });
  });

  /* =========================================================
   * Installed Packages — real package.json/package-lock.json read +
   * cooldown-aware early-approval install (mirrors cooldown_gate.gate_package())
   * ========================================================= */
  let installedLoadedOnce = false;
  let installedRows = [];
  let installedActionState = {};
  let installedAbortController = null;

  function cooldownBadgeHtml(row) {
    if (row.up_to_date) return `<span class="cooldown-badge uptodate">최신</span>`;
    if (!row.cooldown) return `<span class="cooldown-badge uptodate">—</span>`;
    if (row.cooldown.passed) return `<span class="cooldown-badge passed">쿨다운 통과</span>`;
    const remain = row.cooldown.remain_days;
    return `<span class="cooldown-badge holding">쿨다운 중 · ${remain != null ? remain.toFixed(1) : '?'}일 남음</span>`;
  }

  function vulnerabilityBadgeHtml(row) {
    const v = row.vulnerability;
    if (!v) return '<span class="analysis-badge UNKNOWN">미확인</span>';
    if (v.status === 'VULNERABLE') {
      const fixed = v.recommended_version ? ` → ${escapeHtml(v.recommended_version)}` : '';
      return `<span class="analysis-badge VULNERABLE">${v.count || 0}건${fixed}</span>`;
    }
    if (v.status === 'CLEAN') return '<span class="analysis-badge CLEAN">0건</span>';
    return `<span class="analysis-badge ERROR">${escapeHtml(v.status || 'UNKNOWN')}</span>`;
  }

  function targetVersion(row) {
    return row.vulnerability?.recommended_version || row.latest_version;
  }

  function actionCellHtml(row, state) {
    const needsRemediation = row.vulnerability?.status === 'VULNERABLE';
    const target = targetVersion(row);
    if (needsRemediation && !target) return `<span class="muted">공식 완화책 검토</span>`;
    if (!needsRemediation && row.up_to_date) return `<span style="color:var(--muted); font-size:12px;">조치 불필요</span>`;
    if (!needsRemediation && !row.cooldown) return `<span style="color:var(--muted); font-size:12px;">—</span>`;
    const s = state.status;
    if (s === 'checking') return `<div class="scan-status"><span class="spinner"></span><span>검증 중…</span></div>`;
    if (s === 'installing') return `<div class="scan-status"><span class="spinner"></span><span>npm install 실행 중… (최대 3분)</span></div>`;
    if (s === 'approved') return `<div class="install-result approved">${escapeHtml(state.message)}</div><button class="btn small primary" data-action="install" data-name="${escapeHtml(row.name)}" style="margin-top:6px;">${escapeHtml(target)} 설치</button>`;
    if (s === 'blocked') return `<div class="install-result blocked">${escapeHtml(state.message)}</div>`;
    if (s === 'success') return `<div class="install-result success">설치 완료 ✓ (exit 0)${state.stdout ? `<pre class="mono">${escapeHtml(state.stdout.slice(-500))}</pre>` : ''}</div>`;
    if (s === 'fail') return `<div class="install-result fail">설치 실패${state.returncode != null ? ` (exit ${state.returncode})` : ''}${state.stderr ? `<pre class="mono">${escapeHtml(state.stderr.slice(-500))}</pre>` : ''}</div>`;
    if (s === 'error') return `<div class="install-result fail">오류: ${escapeHtml(state.error || '알 수 없는 오류')}</div>`;
    if (needsRemediation) return `<button class="btn small primary" data-action="early_approve" data-name="${escapeHtml(row.name)}">수정 버전 검증</button>`;
    // idle
    if (row.cooldown.passed) return `<button class="btn small" data-action="install" data-name="${escapeHtml(row.name)}">검증 후 설치</button>`;
    return `<button class="btn small" data-action="early_approve" data-name="${escapeHtml(row.name)}">조기 승인 확인</button>`;
  }

  /* 이력에 남은 마지막 판정. 아직 한 번도 검사하지 않은 패키지와, 검사했지만
   * 판정이 UNVERIFIABLE인 패키지는 다른 뜻이므로 구분해서 보여준다. */
  function lastScanHtml(row) {
    const s = row.last_scan;
    if (!s) return '<span class="muted">미검사</span>';
    const when = new Date(s.created_at).toLocaleString('ko-KR');
    const title = `${s.version || ''} · ${s.source || ''} · ${when}${s.reason ? '\n' + s.reason : ''}`;
    return `<span class="verdict-pill ${s.verdict}" title="${escapeHtml(title)}">${s.verdict} · ${s.score ?? 0}</span>`;
  }

  function rowHtml(row) {
    const state = installedActionState[row.name] || { status: 'idle' };
    return `
      <tr>
        <td class="pkg-name-cell">${escapeHtml(row.name)}</td>
        <td class="mono">${row.installed_version || '—'}</td>
        <td class="mono">${row.latest_version || '—'}</td>
        <td>${vulnerabilityBadgeHtml(row)}</td>
        <td>${lastScanHtml(row)}</td>
        <td>${cooldownBadgeHtml(row)}</td>
        <td><div class="install-cell" id="install-cell-${safeId(row.name)}">${actionCellHtml(row, state)}</div></td>
      </tr>
    `;
  }

  function updateInstalledRowCell(row) {
    const cell = document.getElementById('install-cell-' + safeId(row.name));
    if (cell) cell.innerHTML = actionCellHtml(row, installedActionState[row.name] || { status: 'idle' });
  }

  function renderInstalledTable() {
    document.getElementById('installed-tbody').innerHTML = installedRows.map(rowHtml).join('');
  }

  document.getElementById('installed-tbody').addEventListener('click', async (e) => {
    const btn = e.target.closest('button[data-action]');
    if (!btn) return;
    const name = btn.dataset.name;
    const action = btn.dataset.action;
    const row = installedRows.find(r => r.name === name);
    if (!row) return;
    btn.disabled = true;

    if (action === 'early_approve') {
      installedActionState[name] = { status: 'checking' };
      updateInstalledRowCell(row);
      try {
        const res = await fetch('/api/early_approve', {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ package: name, installed_version: row.installed_version, candidate_version: targetVersion(row) }),
        });
        const data = await res.json();
        if (!data.ok) installedActionState[name] = { status: 'error', error: data.error || '알 수 없는 오류' };
        else if (data.approved) installedActionState[name] = { status: 'approved', message: data.message };
        else installedActionState[name] = { status: 'blocked', message: data.message };
      } catch (err) {
        installedActionState[name] = { status: 'error', error: String(err) };
      }
      updateInstalledRowCell(row);
    } else if (action === 'install') {
      const project = document.getElementById('installed-project').value.trim();
      // 경로가 비어 있으면 서버는 기본 대상을 쓴다. 그게 전역이면 이 클릭이
      // `npm install -g` 로 이 PC 전체의 설치 상태를 바꾼다 — 프로젝트 폴더
      // 안에서 끝나는 설치와 달리 영향 범위가 넓으므로 한 번 확인받는다.
      if (!project && defaultScopeIsGlobal) {
        const target = targetVersion(row);
        const proceed = confirm(
          `이 PC의 전역 npm 패키지를 실제로 변경합니다.\n\n`
          + `  npm install -g ${name}@${target}\n\n`
          + `${name}: ${row.installed_version || '(미설치)'} → ${target}\n\n`
          + `계속할까요?`);
        // 취소하면 아무것도 하지 않고 버튼을 되살린다 (상태는 여전히 idle).
        if (!proceed) { updateInstalledRowCell(row); return; }
      }
      installedActionState[name] = { status: 'installing' };
      updateInstalledRowCell(row);
      try {
        const res = await fetch('/api/install', {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ package: name, version: targetVersion(row), project }),
        });
        const data = await res.json();
        if (data.blocked) installedActionState[name] = { status: 'blocked', message: data.message };
        else if (data.ok) installedActionState[name] = { status: 'success', stdout: data.stdout };
        else installedActionState[name] = { status: 'fail', error: data.error, stderr: data.stderr, returncode: data.returncode };
      } catch (err) {
        installedActionState[name] = { status: 'error', error: String(err) };
      }
      updateInstalledRowCell(row);
    }
  });

  async function loadInstalled() {
    // cancel any in-flight load so a stale (e.g. auto-triggered default-project)
    // response can never overwrite a newer explicit request's result
    if (installedAbortController) installedAbortController.abort();
    const myController = new AbortController();
    installedAbortController = myController;

    const statusArea = document.getElementById('installed-status-area');
    const projectInput = document.getElementById('installed-project');
    const project = projectInput.value.trim();
    const loadBtn = document.getElementById('installed-load-btn');
    loadBtn.disabled = true;
    statusArea.innerHTML = `<div class="scan-status"><span class="spinner"></span><span>package.json 읽는 중 + 레지스트리 조회… (패키지 수에 따라 수 초~수십 초)</span></div>`;
    try {
      const q = new URLSearchParams(); if (project) q.set('project', project);
      const res = await fetch('/api/installed?' + q.toString(), { signal: myController.signal });
      const data = await res.json();
      if (installedAbortController !== myController) return; // superseded by a newer load
      statusArea.innerHTML = '';
      if (!data.ok) {
        statusArea.innerHTML = `<div class="scan-error"><b>불러오기 실패</b> — ${escapeHtml(data.error || '알 수 없는 오류')}</div>`;
        document.getElementById('installed-panel').style.display = 'none';
        return;
      }
      installedLoadedOnce = true;
      installedRows = data.packages;
      installedActionState = {};
      if (!project) projectInput.placeholder = data.project;
      document.getElementById('installed-panel').style.display = 'block';
      document.getElementById('installed-monitor-btn').disabled = false;
      renderInstalledTable();
      loadMonitorSnapshot(project);
    } catch (err) {
      if (err.name === 'AbortError') return;
      statusArea.innerHTML = `<div class="scan-error"><b>서버에 연결할 수 없음</b> — ${escapeHtml(String(err))}</div>`;
    } finally {
      if (installedAbortController === myController) loadBtn.disabled = false;
    }
  }
  document.getElementById('installed-load-btn').addEventListener('click', loadInstalled);

  function applyMonitorSnapshot(monitor) {
    if (!monitor || !Array.isArray(monitor.packages)) return;
    const byName = new Map(monitor.packages.map(row => [row.name, row]));
    installedRows.forEach(row => { row.vulnerability = byName.get(row.name) || null; });
    renderInstalledTable();
    const area = document.getElementById('installed-monitor-status');
    area.innerHTML = `<div class="monitor-summary"><b>${escapeHtml(monitor.status || 'UNKNOWN')}</b> · ${monitor.package_count || 0}개 점검 · 취약 ${monitor.vulnerable_count || 0}개 · ${escapeHtml(new Date(monitor.checked_at).toLocaleString('ko-KR'))}</div>`;
  }

  async function loadMonitorSnapshot(project) {
    try {
      const q = new URLSearchParams(); if (project) q.set('project', project);
      const data = await fetch('/api/monitor?' + q.toString()).then(r => r.json());
      if (data.ok && data.monitor) applyMonitorSnapshot(data.monitor);
    } catch { /* 저장된 스냅샷이 없어도 설치 목록은 그대로 쓴다 */ }
  }

  async function runInstalledMonitor() {
    const btn = document.getElementById('installed-monitor-btn');
    const area = document.getElementById('installed-monitor-status');
    btn.disabled = true;
    area.innerHTML = '<div class="scan-status"><span class="spinner"></span><span>OSV에서 설치 버전을 모니터링 중…</span></div>';
    try {
      const project = document.getElementById('installed-project').value.trim();
      const data = await fetch('/api/monitor', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ project }),
      }).then(r => r.json());
      if (data.packages) applyMonitorSnapshot(data);
      else area.innerHTML = `<div class="scan-error"><b>모니터링 실패</b> — ${escapeHtml(data.error || data.reason || '알 수 없는 오류')}</div>`;
    } catch (err) {
      area.innerHTML = `<div class="scan-error"><b>모니터링 실패</b> — ${escapeHtml(String(err))}</div>`;
    } finally { btn.disabled = false; }
  }
  document.getElementById('installed-monitor-btn').addEventListener('click', runInstalledMonitor);

  /* =========================================================
   * Sample scenarios table
   * ========================================================= */
  renderOverview(); renderExplorer(); renderDashboardRecent(); renderCurrentView();
  loadStoredScans();
})();
