const state = {
  me: null,
  config: null,
  smtpCredential: null,
  dnsCredentials: [],
  apiTokens: [],
  domains: [],
  events: [],
  analytics: null,
  users: [],
  settings: null,
  selectedId: null,
  view: 'dashboard',
  detailTab: 'dns',
  dnsTestResults: {},
  busy: false
};

const viewMeta = {
  dashboard: {
    eyebrow: 'Command Center',
    title: '发信控制台',
    subtitle: '总览域名健康、发信趋势和关键配置状态。'
  },
  analytics: {
    eyebrow: 'Analytics',
    title: '统计分析',
    subtitle: '按时间、域名和状态分析发信表现。'
  },
  domains: {
    eyebrow: 'Domains',
    title: '发信域名',
    subtitle: '管理发信域名、DNS 检查和测试发送。'
  },
  dns: {
    eyebrow: 'DNS API',
    title: 'DNS API 凭据',
    subtitle: '按服务商保存多组 DNS 凭据，再绑定到具体域名。'
  },
  smtp: {
    eyebrow: 'SMTP',
    title: 'SMTP 凭据',
    subtitle: '生成可复制的 SMTP 用户名和密码。'
  },
  tokens: {
    eyebrow: 'API Tokens',
    title: '发送 API Token',
    subtitle: '为不同系统创建独立发信 Token。'
  },
  admin: {
    eyebrow: 'Admin',
    title: '系统设置',
    subtitle: '管理员设置默认发信参数和用户状态。'
  }
};

const els = {
  runtimeLine: document.querySelector('#runtimeLine'),
  viewEyebrow: document.querySelector('#viewEyebrow'),
  viewTitle: document.querySelector('#viewTitle'),
  securityNotice: document.querySelector('#securityNotice'),
  dashboardPanel: document.querySelector('#dashboardPanel'),
  analyticsPanel: document.querySelector('#analyticsPanel'),
  accountBox: document.querySelector('#accountBox'),
  userRole: document.querySelector('#userRole'),
  navButtons: document.querySelectorAll('.primary-nav [data-view]'),
  viewPanels: document.querySelectorAll('[data-view-panel]'),
  adminNavButton: document.querySelector('#adminNavButton'),
  addDomainForm: document.querySelector('#addDomainForm'),
  domainDnsCredential: document.querySelector('#domainDnsCredential'),
  domainReadiness: document.querySelector('#domainReadiness'),
  smtpCredentialForm: document.querySelector('#smtpCredentialForm'),
  smtpCredentialState: document.querySelector('#smtpCredentialState'),
  smtpCredentialCopy: document.querySelector('#smtpCredentialCopy'),
  smtpUsername: document.querySelector('#smtpUsername'),
  smtpPassword: document.querySelector('#smtpPassword'),
  generateSmtpPassword: document.querySelector('#generateSmtpPassword'),
  dnsCredentialForm: document.querySelector('#dnsCredentialForm'),
  dnsCredentialFormTitle: document.querySelector('#dnsCredentialFormTitle'),
  dnsCredentialFormHint: document.querySelector('#dnsCredentialFormHint'),
  dnsCredentialIdField: document.querySelector('#dnsCredentialIdField'),
  dnsCredentialName: document.querySelector('#dnsCredentialName'),
  dnsDefaultTtl: document.querySelector('#dnsDefaultTtl'),
  dnsProvider: document.querySelector('#dnsProvider'),
  dnsZoneName: document.querySelector('#dnsZoneName'),
  dnsCredentialList: document.querySelector('#dnsCredentialList'),
  dnsCredentialCount: document.querySelector('#dnsCredentialCount'),
  resetDnsCredentialForm: document.querySelector('#resetDnsCredentialForm'),
  apiTokenForm: document.querySelector('#apiTokenForm'),
  apiTokenList: document.querySelector('#apiTokenList'),
  apiTokenCount: document.querySelector('#apiTokenCount'),
  analyticsEventCount: document.querySelector('#analyticsEventCount'),
  defaultSenderHost: document.querySelector('#defaultSenderHost'),
  defaultSendingIp: document.querySelector('#defaultSendingIp'),
  defaultSpfExtra: document.querySelector('#defaultSpfExtra'),
  domainList: document.querySelector('#domainList'),
  domainCount: document.querySelector('#domainCount'),
  detailPanel: document.querySelector('#detailPanel'),
  adminPanel: document.querySelector('#adminPanel'),
  refreshButton: document.querySelector('#refreshButton'),
  refreshButtonMobile: document.querySelector('#refreshButtonMobile'),
  logoutButton: document.querySelector('#logoutButton'),
  toastHost: document.querySelector('#toastHost')
};

init();

async function init() {
  bindEvents();
  await refreshAll();
}

function bindEvents() {
  els.refreshButton.addEventListener('click', refreshAll);
  els.refreshButtonMobile?.addEventListener('click', refreshAll);
  els.logoutButton.addEventListener('click', logout);
  document.addEventListener('click', handleGlobalClick);
  els.addDomainForm.addEventListener('submit', addDomain);
  els.smtpCredentialForm.addEventListener('submit', saveSmtpCredential);
  els.generateSmtpPassword.addEventListener('click', generateSmtpPassword);
  els.dnsCredentialForm.addEventListener('submit', saveDnsCredential);
  els.dnsProvider.addEventListener('change', toggleDnsProviderFields);
  els.resetDnsCredentialForm.addEventListener('click', resetDnsCredentialForm);
  els.apiTokenForm.addEventListener('submit', createApiToken);
  els.domainList.addEventListener('click', (event) => {
    const item = event.target.closest('[data-domain-id]');
    if (!item) return;
    state.selectedId = Number(item.dataset.domainId);
    state.detailTab = 'dns';
    setView('domains');
    render();
  });
  els.detailPanel.addEventListener('submit', handleDetailSubmit);
  els.adminPanel.addEventListener('submit', handleDetailSubmit);
}

async function refreshAll() {
  setBusy(true);
  try {
    const me = await api('/api/me');
    state.me = me.user;
    const baseCalls = [
      api('/api/config'),
      api('/api/domains'),
      api('/api/events'),
      api('/api/analytics?days=30'),
      api('/api/smtp-credential'),
      api('/api/dns-credentials'),
      api('/api/api-tokens')
    ];
    const [config, domains, events, analytics, smtpCredential, dnsCredentials, apiTokens] = await Promise.all(baseCalls);
    state.config = config;
    state.domains = domains.domains || [];
    state.events = events.events || [];
    state.analytics = analytics.analytics || null;
    state.smtpCredential = smtpCredential.credential || null;
    state.dnsCredentials = dnsCredentials.credentials || [];
    state.apiTokens = apiTokens.tokens || [];
    if (state.me?.role === 'admin') {
      const [settings, users] = await Promise.all([
        api('/api/admin/settings'),
        api('/api/admin/users')
      ]);
      state.settings = settings.settings || null;
      state.users = users.users || [];
    }
    if (!state.selectedId && state.domains.length) state.selectedId = state.domains[0].id;
    if (state.selectedId && !state.domains.some((domain) => domain.id === state.selectedId)) {
      state.selectedId = state.domains[0]?.id || null;
    }
    renderDefaults();
    render();
  } catch (error) {
    toast(error.message, 'error');
  } finally {
    setBusy(false);
  }
}

function renderDefaults() {
  if (!state.config) return;
  const ip = state.config.sendingIp || '未设置发信 IP';
  els.runtimeLine.textContent = `${state.config.mailHostname} · ${ip} · ${viewMeta[state.view]?.subtitle || ''}`;
  els.defaultSenderHost.value = state.config.mailHostname || '';
  els.defaultSendingIp.value = state.config.sendingIp || '';
  els.defaultSpfExtra.value = state.config.defaultSpfMechanisms || '';
  els.smtpUsername.value = state.smtpCredential?.username || state.config.submission?.username || '';
  els.smtpCredentialState.textContent = state.smtpCredential?.passwordSet ? '已配置' : '未配置';
  els.userRole.textContent = state.me?.role === 'admin' ? '管理员' : '用户';
  els.userRole.className = `badge ${state.me?.role === 'admin' ? 'bg-green-lt' : 'bg-secondary-lt'}`;
  els.adminNavButton.classList.toggle('hidden', state.me?.role !== 'admin');
  if (state.me?.role !== 'admin' && state.view === 'admin') setView('domains');
  els.accountBox.innerHTML = `
    <div class="list-group-item px-0 py-2 bg-transparent border-0">
      <div class="text-secondary small">Username</div>
      <code>${escapeHtml(state.me?.username || '')}</code>
    </div>
    <div class="list-group-item px-0 py-2 bg-transparent border-0">
      <div class="text-secondary small">Email</div>
      <code>${escapeHtml(state.me?.email || '')}</code>
    </div>
  `;
  renderDnsOptions();
  renderDashboard();
  renderAnalyticsPanel();
  renderDomainReadiness();
  renderSmtpCredentialCopy();
  renderDnsCredentials();
  renderApiTokens();
  renderAdminPanel();
  renderSecurityNotice();
  toggleDnsProviderFields();
}

function render() {
  els.domainCount.textContent = String(state.domains.length);
  els.dnsCredentialCount.textContent = String(state.dnsCredentials.length);
  els.apiTokenCount.textContent = String(state.apiTokens.length);
  els.analyticsEventCount.textContent = String(state.analytics?.summary?.total || 0);
  renderViewMeta();
  renderDashboard();
  renderAnalyticsPanel();
  renderDomainList();
  renderDetail();
}

function renderViewMeta() {
  const meta = viewMeta[state.view] || viewMeta.domains;
  els.viewEyebrow.textContent = meta.eyebrow;
  els.viewTitle.textContent = meta.title;
  if (state.config) {
    const ip = state.config.sendingIp || '未设置发信 IP';
    els.runtimeLine.textContent = `${state.config.mailHostname} · ${ip} · ${meta.subtitle}`;
  }
  for (const button of els.navButtons) {
    button.classList.toggle('active', button.dataset.view === state.view);
  }
  for (const panel of els.viewPanels) {
    panel.classList.toggle('active', panel.dataset.viewPanel === state.view);
  }
}

function setView(view) {
  if (!viewMeta[view]) return;
  if (view === 'admin' && state.me?.role !== 'admin') return;
  state.view = view;
  renderViewMeta();
}

function renderSecurityNotice() {
  els.securityNotice.classList.toggle('hidden', !state.config.usingDefaultAdminPassword);
  els.securityNotice.textContent = state.config.usingDefaultAdminPassword
    ? '当前仍在使用默认管理密码，请修改 .env 后重启服务。'
    : '';
}

function renderDashboard() {
  if (!els.dashboardPanel) return;
  const analytics = state.analytics || {};
  const summary = analytics.summary || {};
  const totalDomains = state.domains.length;
  const verifiedDomains = state.domains.filter((domain) => domain.status?.verified).length;
  const dnsReady = state.dnsCredentials.length > 0;
  const smtpReady = Boolean(state.smtpCredential?.passwordSet);
  const tokenReady = state.apiTokens.length > 0;
  const domainScore = totalDomains ? (verifiedDomains / totalDomains) * 42 : 0;
  const score = Math.min(100, Math.round(domainScore + (dnsReady ? 18 : 0) + (smtpReady ? 18 : 0) + (tokenReady ? 8 : 0) + ((summary.successRate || 0) * 0.14)));
  const risks = dashboardRisks(summary, { totalDomains, verifiedDomains, dnsReady, smtpReady, tokenReady });
  els.dashboardPanel.innerHTML = `
    <section class="console-hero">
      <div class="console-copy">
        <span class="eyebrow">MailHub Command Center</span>
        <h2>多租户发信运营后台</h2>
        <p>${escapeHtml(state.config?.mailHostname || 'mail host')} · ${escapeHtml(state.config?.sendingIp || '未设置发信 IP')} · ${escapeHtml(state.me?.email || '')}</p>
        <div class="hero-actions">
          <button class="btn btn-primary" data-view="domains" type="button"><i class="ti ti-world-plus"></i> 添加域名</button>
          <button class="btn btn-outline-secondary" data-view="analytics" type="button"><i class="ti ti-chart-histogram"></i> 查看分析</button>
        </div>
      </div>
      <div class="health-orbit" style="--score: ${score}%">
        <span>健康评分</span>
        <strong>${score}</strong>
        <small>${score >= 90 ? '运行良好' : score >= 70 ? '仍有优化项' : '需要配置'}</small>
      </div>
    </section>

    <section class="ops-grid">
      ${kpiTile('今日发送', summary.today || 0, `${summary.last7Days || 0} / 近 7 日`, 'ti-send', 'cyan')}
      ${kpiTile('成功率', `${summary.successRate || 0}%`, `${summary.queued || 0} 成功 / ${summary.failed || 0} 失败`, 'ti-shield-check', 'green')}
      ${kpiTile('域名健康', `${verifiedDomains}/${totalDomains}`, '已验证发信域名', 'ti-world-check', 'blue')}
      ${kpiTile('收件人触达', summary.recipients || 0, '统计窗口内收件人数', 'ti-users', 'amber')}
    </section>

    <section class="dashboard-layout">
      <div class="data-panel trend-panel">
        <div class="panel-heading">
          <div>
            <span class="eyebrow">Traffic</span>
            <h3>近 14 日发信趋势</h3>
          </div>
          <span class="badge bg-cyan-lt">${summary.total || 0} events</span>
        </div>
        ${renderDailyBars((analytics.byDay || []).slice(-14))}
      </div>

      <div class="data-panel">
        <div class="panel-heading">
          <div>
            <span class="eyebrow">Readiness</span>
            <h3>上线检查</h3>
          </div>
        </div>
        <div class="readiness-list">
          ${readinessItem('DNS API', dnsReady, dnsReady ? `${state.dnsCredentials.length} 组可用` : '需要添加 DNS API')}
          ${readinessItem('SMTP 凭据', smtpReady, smtpReady ? state.smtpCredential.username : '需要设置平台凭据')}
          ${readinessItem('发信域名', Boolean(totalDomains), totalDomains ? `${verifiedDomains} 个已验证` : '需要添加域名')}
          ${readinessItem('API Token', tokenReady, tokenReady ? `${state.apiTokens.length} 个 Token` : '建议创建发送 Token')}
        </div>
      </div>

      <div class="data-panel">
        <div class="panel-heading">
          <div>
            <span class="eyebrow">Focus</span>
            <h3>待处理事项</h3>
          </div>
        </div>
        ${renderRiskList(risks)}
      </div>
    </section>
  `;
}

function renderAnalyticsPanel() {
  if (!els.analyticsPanel) return;
  const analytics = state.analytics || {};
  const summary = analytics.summary || {};
  const statusTotal = Math.max(1, summary.total || 0);
  const queuedRatio = Math.round(((summary.queued || 0) / statusTotal) * 100);
  els.analyticsPanel.innerHTML = `
    <section class="analysis-head">
      <div>
        <span class="eyebrow">Analytics Window</span>
        <h2>${analytics.windowDays || 30} 天发信分析</h2>
        <p>${escapeHtml(state.me?.username || '')} 的独立数据视图，按用户隔离统计。</p>
      </div>
      <div class="analysis-summary">
        ${miniMetric('总发送', summary.total || 0)}
        ${miniMetric('今日', summary.today || 0)}
        ${miniMetric('成功率', `${summary.successRate || 0}%`)}
      </div>
    </section>

    <section class="analysis-grid">
      <div class="data-panel analysis-wide">
        <div class="panel-heading">
          <div><span class="eyebrow">Daily Volume</span><h3>每日发送量</h3></div>
          <span class="badge bg-blue-lt">${summary.recipients || 0} recipients</span>
        </div>
        ${renderDailyBars(analytics.byDay || [])}
      </div>

      <div class="data-panel">
        <div class="panel-heading">
          <div><span class="eyebrow">Status</span><h3>状态分布</h3></div>
        </div>
        <div class="status-donut" style="--queued: ${queuedRatio}%">
          <strong>${queuedRatio}%</strong>
          <span>queued</span>
        </div>
        <div class="status-legend">
          ${(analytics.byStatus || []).map((item) => `<div><span>${escapeHtml(statusLabel(item.status))}</span><strong>${escapeHtml(item.total)}</strong></div>`).join('') || '<p class="text-secondary">暂无发送数据</p>'}
        </div>
      </div>

      <div class="data-panel">
        <div class="panel-heading">
          <div><span class="eyebrow">Domains</span><h3>域名排行</h3></div>
        </div>
        ${renderDomainLeaderboard(analytics.byDomain || [])}
      </div>

      <div class="data-panel">
        <div class="panel-heading">
          <div><span class="eyebrow">Hour Map</span><h3>24 小时热力</h3></div>
        </div>
        ${renderHourlyHeatmap(analytics.hourly || [])}
      </div>

      <div class="data-panel analysis-wide">
        <div class="panel-heading">
          <div><span class="eyebrow">Failures</span><h3>最近失败</h3></div>
        </div>
        ${renderFailureList(analytics.recentFailures || [])}
      </div>
    </section>
  `;
}

function dashboardRisks(summary, flags) {
  const risks = [];
  if (!flags.smtpReady) risks.push({ tone: 'failed', title: 'SMTP 凭据未配置', detail: '客户端无法完成 SMTP Submission 认证。' });
  if (!flags.dnsReady) risks.push({ tone: 'warn', title: 'DNS API 未配置', detail: '域名需要手动复制 DNS 记录。' });
  if (flags.totalDomains && flags.verifiedDomains < flags.totalDomains) risks.push({ tone: 'warn', title: '存在未验证域名', detail: `${flags.totalDomains - flags.verifiedDomains} 个域名仍需检查 DNS。` });
  if ((summary.failed || 0) > 0) risks.push({ tone: 'failed', title: '近期有发送失败', detail: `${summary.failed} 条失败记录，建议查看失败原因。` });
  if (!flags.tokenReady) risks.push({ tone: 'idle', title: '未创建 API Token', detail: '生产系统建议使用独立 Token 接入。' });
  return risks;
}

function renderRiskList(risks) {
  if (!risks.length) return '<div class="empty-soft">暂无待处理事项</div>';
  return `<div class="risk-list">${risks.map((risk) => `
    <div class="risk-row ${risk.tone}">
      ${badge({ className: risk.tone, label: risk.tone === 'failed' ? '重点' : risk.tone === 'warn' ? '注意' : '建议' })}
      <div><strong>${escapeHtml(risk.title)}</strong><span>${escapeHtml(risk.detail)}</span></div>
    </div>
  `).join('')}</div>`;
}

function kpiTile(label, value, hint, icon, tone) {
  return `
    <article class="kpi-tile ${tone}">
      <i class="ti ${icon}" aria-hidden="true"></i>
      <span>${escapeHtml(label)}</span>
      <strong>${escapeHtml(value)}</strong>
      <small>${escapeHtml(hint || '')}</small>
    </article>
  `;
}

function miniMetric(label, value) {
  return `<div><span>${escapeHtml(label)}</span><strong>${escapeHtml(value)}</strong></div>`;
}

function readinessItem(label, ready, detail) {
  return `
    <div class="readiness-item ${ready ? 'ok' : 'warn'}">
      <i class="ti ${ready ? 'ti-circle-check' : 'ti-alert-triangle'}" aria-hidden="true"></i>
      <div><strong>${escapeHtml(label)}</strong><span>${escapeHtml(detail)}</span></div>
    </div>
  `;
}

function renderDailyBars(days) {
  if (!days.length || !days.some((day) => day.total)) return '<div class="empty-soft">暂无发送数据</div>';
  const max = Math.max(...days.map((day) => day.total), 1);
  return `
    <div class="bar-chart">
      ${days.map((day) => {
        const totalHeight = Math.max(4, Math.round((day.total / max) * 100));
        const queuedHeight = day.total ? Math.round((day.queued / day.total) * totalHeight) : 0;
        const failedHeight = Math.max(0, totalHeight - queuedHeight);
        return `
          <div class="bar-column" title="${escapeAttr(day.day)} · ${escapeAttr(day.total)}">
            <div class="bar-track">
              <span class="bar-failed" style="height:${failedHeight}%"></span>
              <span class="bar-queued" style="height:${queuedHeight}%"></span>
            </div>
            <small>${escapeHtml(day.day.slice(5))}</small>
          </div>
        `;
      }).join('')}
    </div>
  `;
}

function renderDomainLeaderboard(rows) {
  if (!rows.length) return '<div class="empty-soft">暂无域名发送数据</div>';
  const max = Math.max(...rows.map((row) => row.total), 1);
  return `<div class="leaderboard">${rows.map((row) => `
    <div class="leader-row">
      <div><strong>${escapeHtml(row.domain)}</strong><span>${escapeHtml(row.queued)} 成功 / ${escapeHtml(row.failed)} 失败</span></div>
      <div class="leader-meter"><span style="width:${Math.round((row.total / max) * 100)}%"></span></div>
      <b>${escapeHtml(row.total)}</b>
    </div>
  `).join('')}</div>`;
}

function renderHourlyHeatmap(rows) {
  const max = Math.max(...rows.map((row) => row.total), 1);
  return `<div class="hour-grid">${rows.map((row) => {
    const level = row.total ? Math.max(1, Math.ceil((row.total / max) * 4)) : 0;
    return `<span class="hour-cell level-${level}" title="${row.hour}:00 · ${row.total}">${String(row.hour).padStart(2, '0')}</span>`;
  }).join('')}</div>`;
}

function renderFailureList(rows) {
  if (!rows.length) return '<div class="empty-soft">暂无失败记录</div>';
  return `<div class="failure-list">${rows.map((row) => `
    <div class="failure-row">
      <div><strong>${escapeHtml(row.subject || '(no subject)')}</strong><span>${escapeHtml(row.sender)} · ${escapeHtml(formatDate(row.createdAt))}</span></div>
      <code>${escapeHtml(row.detail || '未返回错误详情')}</code>
    </div>
  `).join('')}</div>`;
}

function renderDomainReadiness() {
  const verified = state.domains.filter((domain) => domain.status?.verified).length;
  const latestEvent = state.events[0];
  els.domainReadiness.innerHTML = `
    <div class="card-header">
      <div>
        <h3 class="card-title">运行概览</h3>
        <p class="card-subtitle">关键配置集中在这里，缺哪一项就先补哪一项。</p>
      </div>
    </div>
    <div class="card-body">
      <div class="row row-cards">
        ${metricCard('域名', state.domains.length, `${verified} 个已通过`)}
        ${metricCard('DNS API', state.dnsCredentials.length, state.dnsCredentials.length ? '可一键写入' : '尚未配置')}
        ${metricCard('SMTP', state.smtpCredential?.passwordSet ? 'Ready' : 'Missing', state.smtpCredential?.username || '未设置凭据')}
        ${metricCard('最近发送', latestEvent ? formatDate(latestEvent.createdAt) : '暂无', latestEvent?.status || '无记录')}
      </div>
      <div class="d-flex flex-wrap gap-2 mt-3">
        ${!state.dnsCredentials.length ? '<button class="btn btn-outline-secondary" data-view="dns" type="button">新增 DNS API</button>' : ''}
        ${!state.smtpCredential?.passwordSet ? '<button class="btn btn-outline-secondary" data-view="smtp" type="button">设置 SMTP</button>' : ''}
        <button class="btn btn-outline-secondary" data-action="check" type="button" ${state.selectedId ? '' : 'disabled'}>检查当前域名</button>
      </div>
    </div>
  `;
}

function metricCard(label, value, hint) {
  return `
    <div class="col-sm-6">
      <div class="card card-sm metric-card">
        <div class="card-body">
          <div class="text-secondary small">${escapeHtml(label)}</div>
          <div class="h2 m-0">${escapeHtml(value)}</div>
          <div class="text-secondary small">${escapeHtml(hint || '')}</div>
        </div>
      </div>
    </div>
  `;
}

function renderDnsOptions(selectedId = '') {
  const activeId = selectedId || els.domainDnsCredential.value || '';
  if (!state.dnsCredentials.length) {
    els.domainDnsCredential.innerHTML = '<option value="">未绑定，先手动配置或新增 DNS API</option>';
    return;
  }
  const options = [
    '<option value="">不绑定，手动配置</option>',
    ...state.dnsCredentials.map((credential) => `
      <option value="${credential.id}" ${String(activeId) === String(credential.id) ? 'selected' : ''}>
        ${escapeHtml(credential.name)} · ${providerLabel(credential.provider)} · ${escapeHtml(credential.zoneName || '未设置 Zone')}
      </option>
    `)
  ].join('');
  els.domainDnsCredential.innerHTML = options;
}

function renderSmtpCredentialCopy() {
  const credential = state.smtpCredential;
  if (!credential?.username && !credential?.passwordSet) {
    els.smtpCredentialCopy.innerHTML = `
      <div class="empty">
        <div class="empty-title">还没有 SMTP 凭据</div>
        <p>保存用户名和密码后，这里会显示可复制内容。</p>
      </div>
    `;
    return;
  }
  const password = credential?.password || '';
  els.smtpCredentialCopy.innerHTML = `
    <div class="copy-row">
      <span>Username</span>
      <code>${escapeHtml(credential.username || '')}</code>
      <button class="btn btn-sm btn-outline-secondary" data-copy="${escapeAttr(credential.username || '')}" type="button">复制</button>
    </div>
    <div class="copy-row">
      <span>Password</span>
      ${password
        ? `<code>${escapeHtml(password)}</code><button class="btn btn-sm btn-outline-secondary" data-copy="${escapeAttr(password)}" type="button">复制</button>`
        : '<p class="text-secondary">旧密码无法回显，请重新设置一次新密码后复制。</p>'}
    </div>
  `;
}

function renderDnsCredentials() {
  els.dnsCredentialCount.textContent = String(state.dnsCredentials.length);
  if (!state.dnsCredentials.length) {
    els.dnsCredentialList.innerHTML = `
      <div class="empty">
        <div class="empty-title">暂无 DNS API 凭据</div>
        <p>先在右侧新增一组凭据；添加域名时下拉框就会出现可选项。</p>
      </div>
    `;
    return;
  }
  els.dnsCredentialList.innerHTML = state.dnsCredentials.map((credential) => `
    <article class="card credential-row">
      <div class="card-body">
        <div>
          <div class="d-flex align-items-center justify-content-between gap-2 mb-1">
            <strong>${escapeHtml(credential.name)}</strong>
            ${badge({ className: credential.credentialSet ? 'ok' : 'warn', label: credential.credentialSet ? '已保存' : '缺密钥' })}
          </div>
          <span class="text-secondary">${providerLabel(credential.provider)} · ${escapeHtml(credential.zoneName || '未设置 Zone')} · TTL ${escapeHtml(credential.defaultTtl)}</span>
          ${renderDnsTestResult(credential.id)}
        </div>
        <div class="d-flex flex-wrap gap-2 justify-content-end">
          <button class="btn btn-sm btn-outline-secondary" data-action="edit-dns" data-id="${credential.id}" type="button">编辑</button>
          <button class="btn btn-sm btn-outline-secondary" data-action="test-dns" data-id="${credential.id}" type="button">测试</button>
          <button class="btn btn-sm btn-outline-danger" data-action="delete-dns" data-id="${credential.id}" type="button">删除</button>
        </div>
      </div>
    </article>
  `).join('');
}

function renderDnsTestResult(id) {
  const result = state.dnsTestResults[id];
  if (!result) return '';
  return `
    <div class="dns-test-result ${result.ok ? 'ok' : 'failed'}">
      <i class="ti ${result.ok ? 'ti-plug-connected' : 'ti-plug-connected-x'}" aria-hidden="true"></i>
      <span>${escapeHtml(result.message)}</span>
    </div>
  `;
}

function renderApiTokens() {
  els.apiTokenCount.textContent = String(state.apiTokens.length);
  if (!state.apiTokens.length) {
    els.apiTokenList.innerHTML = `
      <div class="empty">
        <div class="empty-title">暂无发送 Token</div>
        <p>创建后请立即保存完整 Token，页面之后只显示前缀。</p>
      </div>
    `;
    return;
  }
  els.apiTokenList.innerHTML = state.apiTokens.map((token) => `
    <div class="mini-row">
      <div>
        <strong>${escapeHtml(token.name)}</strong>
        <span class="text-secondary">${escapeHtml(token.tokenPrefix)}... · ${escapeHtml(formatDate(token.createdAt))}</span>
      </div>
      <button class="btn btn-sm btn-outline-danger" data-action="delete-token" data-id="${token.id}" type="button">删除</button>
    </div>
  `).join('');
}

function renderAdminPanel() {
  if (state.me?.role !== 'admin') {
    els.adminPanel.classList.add('hidden');
    els.adminPanel.innerHTML = '';
    return;
  }
  const settings = state.settings || state.config || {};
  els.adminPanel.classList.remove('hidden');
  els.adminPanel.innerHTML = `
    <div class="card-header">
      <div>
        <h3 class="card-title">系统默认值</h3>
        <p class="card-subtitle">这些值会作为新域名的默认 DNS 和发信参数。</p>
      </div>
      <div class="card-actions">
        <span class="badge bg-blue-lt">${state.users.length} 用户</span>
      </div>
    </div>
    <div class="card-body">
      <form class="compact-form" data-form="admin-settings">
        <div class="mb-3">
          <label class="form-label">APP Base URL</label>
          <input class="form-control" name="appBaseUrl" value="${escapeAttr(settings.appBaseUrl || '')}">
          <div class="form-hint">API 示例和外部访问地址。</div>
        </div>
        <div class="row">
          <div class="col-sm-6 mb-3">
            <label class="form-label">发信主机</label>
            <input class="form-control" name="mailHostname" value="${escapeAttr(settings.mailHostname || '')}">
            <div class="form-hint">建议使用 mail.example.com。</div>
          </div>
          <div class="col-sm-6 mb-3">
            <label class="form-label">发信 IP</label>
            <input class="form-control" name="sendingIp" value="${escapeAttr(settings.sendingIp || '')}">
            <div class="form-hint">服务器公网 IPv4。</div>
          </div>
        </div>
        <div class="mb-3">
          <label class="form-label">默认 SPF</label>
          <textarea class="form-control" name="defaultSpfMechanisms" rows="2">${escapeHtml(settings.defaultSpfMechanisms || '')}</textarea>
          <div class="form-hint">会合并到 v=spf1 中，不要重复写 v=spf1。</div>
        </div>
        <div class="row">
          <div class="col-sm-6 mb-3">
            <label class="form-label">DMARC</label>
            <select class="form-select" name="dmarcPolicy">
              ${['none', 'quarantine', 'reject'].map((value) => `<option value="${value}" ${settings.dmarcPolicy === value ? 'selected' : ''}>${value}</option>`).join('')}
            </select>
          </div>
          <div class="col-sm-6 mb-3">
            <label class="form-label">验证后发信</label>
            <select class="form-select" name="sendRequiresVerified">
              <option value="false" ${!settings.sendRequiresVerified ? 'selected' : ''}>否</option>
              <option value="true" ${settings.sendRequiresVerified ? 'selected' : ''}>是</option>
            </select>
          </div>
        </div>
        <div class="mb-3">
          <label class="form-label">DMARC rua</label>
          <input class="form-control" name="dmarcRua" value="${escapeAttr(settings.dmarcRua || '')}" placeholder="mailto:dmarc@example.com">
        </div>
        <button class="btn btn-primary" type="submit">保存系统设置</button>
      </form>
    </div>
    <div class="card-header border-top">
      <div>
        <h3 class="card-title">用户状态</h3>
        <p class="card-subtitle">禁用用户后，该用户的控制台、API Token 和 SMTP 认证都会失效。</p>
      </div>
    </div>
    <div class="card-body">
      <div class="mini-list user-mini-list">
      ${state.users.slice(0, 12).map((user) => `
        <div class="mini-row">
          <div>
            <strong>${escapeHtml(user.username)}</strong>
            <span class="text-secondary">${escapeHtml(user.email)} · ${escapeHtml(user.role)} · ${escapeHtml(user.status)}</span>
          </div>
          <button class="btn btn-sm ${user.status === 'active' ? 'btn-outline-danger' : 'btn-outline-secondary'}" data-action="toggle-user" data-id="${user.id}" data-status="${user.status}" type="button">
            ${user.status === 'active' ? '禁用' : '启用'}
          </button>
        </div>
      `).join('')}
      </div>
    </div>
  `;
}

function renderDomainList() {
  if (!state.domains.length) {
    els.domainList.innerHTML = '<div class="empty-mini">暂无域名</div>';
    return;
  }
  els.domainList.innerHTML = state.domains.map((domain) => {
    const status = statusMeta(domain.status);
    return `
      <button class="domain-item ${domain.id === state.selectedId ? 'active' : ''}" data-domain-id="${domain.id}" type="button">
        <span>${escapeHtml(domain.domain)}</span>
        ${badge(status)}
        <small>${escapeHtml(domain.selector)}._domainkey</small>
      </button>
    `;
  }).join('');
}

function renderDetail() {
  const domain = state.domains.find((item) => item.id === state.selectedId);
  if (!domain) {
    els.detailPanel.innerHTML = `
      <div class="empty-state">
        <h2>选择或添加一个域名</h2>
        <p>DNS 引导、验证结果、DKIM 记录和测试发送会显示在这里。</p>
      </div>
    `;
    return;
  }
  const guide = domain.status || {};
  const records = guide.records || [];
  const warnings = guide.warnings || [];
  const checkedAt = guide.checkedAt ? formatDate(guide.checkedAt) : '尚未检查';
  const applyDisabled = domain.dnsCredentialId ? '' : 'disabled';
  const applyTitle = domain.dnsCredentialId ? '一键配置 DNS' : '请先在域名设置里绑定 DNS API 凭据';
  els.detailPanel.innerHTML = `
    <div class="card-header detail-header">
      <div>
        <h3 class="card-title">${escapeHtml(domain.domain)}</h3>
        <div class="status-strip">
          ${badge(statusMeta(guide))}
          <span class="badge bg-secondary-lt">最近检查 ${escapeHtml(checkedAt)}</span>
          <span class="badge bg-secondary-lt">Selector ${escapeHtml(domain.selector)}</span>
        </div>
      </div>
      <div class="card-actions detail-actions">
        <button class="btn btn-primary" data-action="apply-dns" title="${escapeAttr(applyTitle)}" type="button" ${applyDisabled}>一键配置 DNS</button>
        <button class="btn btn-outline-secondary" data-action="check" type="button">立即检查</button>
        <button class="btn btn-outline-secondary" data-action="rotate-dkim" type="button">轮换 DKIM</button>
        <button class="btn btn-outline-danger" data-action="delete-domain" type="button">删除</button>
      </div>
    </div>
    <div class="card-body detail-body">
      ${renderSetupOverview(domain, guide, records)}
      ${warnings.length ? renderWarnings(warnings) : ''}
      ${renderDetailTabs()}
      ${renderDetailTabContent(domain, guide, records)}
    </div>
  `;
}

function renderDetailTabs() {
  const tabs = [
    ['dns', 'DNS 配置', 'ti-dns'],
    ['settings', '域名设置', 'ti-adjustments'],
    ['send', '测试发送', 'ti-send'],
    ['integrations', '接入方式', 'ti-plug-connected'],
    ['events', '发送记录', 'ti-list-details']
  ];
  return `
    <div class="detail-tabs" role="tablist">
      ${tabs.map(([key, label, icon]) => `
        <button class="${state.detailTab === key ? 'active' : ''}" data-action="detail-tab" data-tab="${key}" type="button">
          <i class="ti ${icon}" aria-hidden="true"></i>
          <span>${label}</span>
        </button>
      `).join('')}
    </div>
  `;
}

function renderDetailTabContent(domain, guide, records) {
  if (state.detailTab === 'settings') {
    return `
      <section class="detail-tab-panel">
        <div class="row row-cards">
          <section class="col-lg-7">
            <div class="card subpanel">
              <div class="card-header"><h3 class="card-title">域名设置</h3></div>
              <div class="card-body">${renderSettingsForm(domain)}</div>
            </div>
          </section>
          <section class="col-lg-5">
            <div class="card subpanel">
              <div class="card-header"><h3 class="card-title">增强安全记录</h3></div>
              <div class="card-body">${renderOptionalRecords(guide.optionalRecords || [])}</div>
            </div>
          </section>
        </div>
      </section>
    `;
  }
  if (state.detailTab === 'send') {
    return `
      <section class="detail-tab-panel">
        <div class="row row-cards">
          <section class="col-lg-5">
            <div class="card subpanel">
              <div class="card-header"><h3 class="card-title">测试发送</h3></div>
              <div class="card-body">${renderSendForm(domain)}</div>
            </div>
          </section>
          <section class="col-lg-7">
            <div class="card subpanel">
              <div class="card-header"><h3 class="card-title">最近发送</h3></div>
              <div class="card-body">${renderEvents(domain)}</div>
            </div>
          </section>
        </div>
      </section>
    `;
  }
  if (state.detailTab === 'integrations') {
    return `
      <section class="detail-tab-panel">
        <div class="row row-cards">
          <section class="col-lg-6">
            <div class="card subpanel api-box">
              <div class="card-header"><h3 class="card-title">发送 API</h3></div>
              <div class="card-body"><pre><code>${escapeHtml(apiExample(domain))}</code></pre></div>
            </div>
          </section>
          <section class="col-lg-6">
            <div class="card subpanel">
              <div class="card-header"><h3 class="card-title">SMTP 发信</h3></div>
              <div class="card-body">${renderSmtpBox(domain)}</div>
            </div>
          </section>
        </div>
      </section>
    `;
  }
  if (state.detailTab === 'events') {
    return `
      <section class="detail-tab-panel">
        <div class="card subpanel">
          <div class="card-header"><h3 class="card-title">发送记录</h3></div>
          <div class="card-body">${renderEvents(domain, 20)}</div>
        </div>
      </section>
    `;
  }
  return `
    <section class="detail-tab-panel">
      ${guide.apply ? renderApplyResult(guide.apply) : ''}
      <div class="row row-cards">
        <section class="col-lg-7">
          <div class="card subpanel">
            <div class="card-header">
              <h3 class="card-title">配置引导</h3>
              <div class="card-actions"><button class="btn btn-sm btn-outline-secondary" data-action="copy-all-dns" type="button">复制全部</button></div>
            </div>
            <div class="card-body">${renderDnsGuide(records)}</div>
          </div>
        </section>
        <section class="col-lg-5">
          <div class="card subpanel">
            <div class="card-header"><h3 class="card-title">当前 DNS</h3></div>
            <div class="card-body">${renderLiveDns(guide.live)}</div>
          </div>
        </section>
      </div>
    </section>
  `;
}

function renderSetupOverview(domain, guide, records) {
  const important = [['verification', '域名验证'], ['dkim', 'DKIM'], ['spf', 'SPF'], ['dmarc', 'DMARC'], ['ptr', 'PTR']];
  const cards = important.map(([key, label]) => {
    const record = records.find((item) => item.key === key);
    const meta = statusMeta(record || {});
    return `<div class="metric-card compact"><span>${escapeHtml(label)}</span><strong>${record ? escapeHtml(meta.label) : '待生成'}</strong></div>`;
  }).join('');
  const credential = state.dnsCredentials.find((item) => item.id === domain.dnsCredentialId);
  return `
    <section class="guide-hero">
      <div>
        <span class="eyebrow">Sending domain</span>
        <h3>${escapeHtml(domain.domain)}</h3>
        <p>${escapeHtml(domain.senderHost)} / ${escapeHtml(domain.sendingIp || '未设置 IP')}</p>
        <p>${credential ? `DNS API: ${escapeHtml(credential.name)}` : 'DNS API: 未绑定'}</p>
      </div>
      <div class="summary-grid">${cards}</div>
    </section>
  `;
}

function renderApplyResult(apply) {
  const rows = apply.results || [];
  return `
    <section class="card subpanel">
      <div class="card-header">
        <h3 class="card-title">一键配置结果</h3>
        <div class="card-actions">${badge({ className: apply.ok ? 'ok' : 'warn', label: apply.ok ? '完成' : '部分失败' })}</div>
      </div>
      <div class="card-body mini-list">
        ${rows.map((row) => `
          <div class="mini-row">
            <div>
              <strong>${escapeHtml(row.key)} · ${escapeHtml(row.type)}</strong>
              <span class="text-secondary">${escapeHtml(row.host)} · ${escapeHtml(row.detail || row.error || '')}</span>
            </div>
            ${badge({ className: row.ok ? 'ok' : 'failed', label: row.ok ? '成功' : '失败' })}
          </div>
        `).join('')}
      </div>
    </section>
  `;
}

function renderDnsGuide(records) {
  if (!records.length) {
    return `
      <div class="empty">
        <div class="empty-title">尚未生成检查结果</div>
        <p>点击“立即检查”后会生成域名验证、DKIM、SPF、DMARC 和 PTR 引导。</p>
      </div>
    `;
  }
  return `<div class="record-steps">${records.map((record, index) => renderRecordCard(record, index + 1)).join('')}</div>`;
}

function renderRecordCard(record, index) {
  const meta = statusMeta(record);
  const current = Array.isArray(record.current) ? record.current : (record.current ? [record.current] : []);
  const warnings = record.warnings || [];
  return `
    <article class="record-card ${meta.className}">
      <div class="record-step"><span>${index}</span></div>
      <div class="record-card-body">
        <div class="record-card-title">
          <div>
            <h4>${escapeHtml(record.label)}</h4>
            <p>${escapeHtml(record.type)} · ${escapeHtml(record.host)}</p>
            ${record.managed ? '<p class="managed-note">平台维护，无需在当前域名 DNS 中配置。</p>' : ''}
          </div>
          ${badge(meta)}
        </div>
        <div class="dns-value">
          <span>目标值</span>
          <code>${escapeHtml(record.value || '')}</code>
          ${record.managed ? '' : `<button class="btn btn-sm btn-outline-secondary" data-copy="${escapeAttr(record.value || '')}" type="button">复制值</button>`}
        </div>
        ${current.length ? `<div class="dns-current"><span>当前值</span>${current.map((value) => `<code>${escapeHtml(value)}</code>`).join('')}</div>` : ''}
        ${warnings.length ? `<ul class="inline-warnings">${warnings.map((warning) => `<li>${escapeHtml(warning)}</li>`).join('')}</ul>` : ''}
      </div>
    </article>
  `;
}

function renderRecordTable(records) {
  if (!records.length) return '<p class="text-secondary">点击“立即检查”生成 SPF、DKIM、DMARC 和 PTR 检查结果。</p>';
  return `
    <div class="record-table-wrap">
      <table class="table table-vcenter">
        <thead><tr><th>项目</th><th>主机</th><th>类型</th><th>目标值</th><th>状态</th><th></th></tr></thead>
        <tbody>${records.map(renderRecordRow).join('')}</tbody>
      </table>
    </div>
  `;
}

function renderRecordRow(record) {
  const meta = statusMeta(record);
  return `
    <tr>
      <td>${escapeHtml(record.label)}</td>
      <td class="mono">${escapeHtml(record.host)}</td>
      <td>${escapeHtml(record.type)}</td>
      <td><code>${escapeHtml(record.value || '')}</code></td>
      <td>${badge(meta)}</td>
      <td><button class="btn btn-sm btn-outline-secondary" data-copy="${escapeAttr(record.value || '')}" type="button">复制</button></td>
    </tr>
  `;
}

function renderSettingsForm(domain) {
  const dnsOptions = [
    '<option value="">不绑定，手动配置</option>',
    ...state.dnsCredentials.map((credential) => `<option value="${credential.id}" ${domain.dnsCredentialId === credential.id ? 'selected' : ''}>${escapeHtml(credential.name)} · ${providerLabel(credential.provider)}</option>`)
  ].join('');
  return `
    <form class="compact-form" data-form="settings">
      <div class="mb-3">
        <label class="form-label">DNS API</label>
        <select class="form-select" name="dnsCredentialId">${dnsOptions}</select>
        <div class="form-hint">绑定后才能使用一键配置 DNS。</div>
      </div>
      <div class="row">
        <div class="col-sm-6 mb-3">
          <label class="form-label">DKIM selector</label>
          <input class="form-control" name="selector" value="${escapeAttr(domain.selector)}">
          <div class="form-hint">轮换 DKIM 时也会重新生成 selector。</div>
        </div>
        <div class="col-sm-6 mb-3">
          <label class="form-label">DMARC 策略</label>
          <select class="form-select" name="dmarcPolicy">${['none', 'quarantine', 'reject'].map((value) => `<option value="${value}" ${domain.dmarcPolicy === value ? 'selected' : ''}>${value}</option>`).join('')}</select>
        </div>
      </div>
      <div class="mb-3"><label class="form-label">发信主机</label><input class="form-control" name="senderHost" value="${escapeAttr(domain.senderHost)}"></div>
      <div class="mb-3"><label class="form-label">发信 IP</label><input class="form-control" name="sendingIp" value="${escapeAttr(domain.sendingIp)}"></div>
      <div class="mb-3"><label class="form-label">兼容第三方 SPF</label><textarea class="form-control" name="spfExtra" rows="3">${escapeHtml(domain.spfExtra || '')}</textarea></div>
      <div class="mb-3"><label class="form-label">DMARC rua</label><input class="form-control" name="dmarcRua" value="${escapeAttr(domain.dmarcRua || '')}" placeholder="mailto:dmarc@example.com"></div>
      <button class="btn btn-outline-secondary" type="submit">保存设置</button>
    </form>
  `;
}

function renderLiveDns(live) {
  if (!live) return '<p class="text-secondary">暂无检查数据</p>';
  const rows = [['根域 TXT', live.rootTxt], ['验证 TXT', live.verificationTxt], ['DKIM TXT', live.dkimTxt], ['DMARC TXT', live.dmarcTxt], ['发信主机 A', live.senderA], ['发信 IP PTR', live.ptr]];
  return `<div class="live-list">${rows.map(([label, values]) => `<div class="live-row"><span>${label}</span>${(values && values.length) ? values.map((value) => `<code>${escapeHtml(value)}</code>`).join('') : '<p class="text-secondary">未发现</p>'}</div>`).join('')}</div>`;
}

function renderSendForm(domain) {
  return `
    <form class="send-form" data-form="send">
      <div class="mb-3"><label class="form-label">From</label><input class="form-control" name="from" value="noreply@${escapeAttr(domain.domain)}"></div>
      <div class="mb-3"><label class="form-label">To</label><input class="form-control" name="to" placeholder="user@example.com" required></div>
      <div class="mb-3"><label class="form-label">Subject</label><input class="form-control" name="subject" value="MailHub test for ${escapeAttr(domain.domain)}"></div>
      <div class="mb-3"><label class="form-label">Text</label><textarea class="form-control" name="text" rows="5">This is a MailHub test message from ${escapeHtml(domain.domain)}.</textarea></div>
      <button class="btn btn-primary" type="submit">发送测试</button>
    </form>
  `;
}

function renderEvents(domain, limit = 8) {
  const events = state.events.filter((event) => event.domain === domain.domain).slice(0, limit);
  if (!events.length) return '<p class="text-secondary">暂无发送记录</p>';
  return `<div class="event-list">${events.map((event) => `<div class="event-row"><div class="item-line"><strong>${escapeHtml(event.subject)}</strong>${badge({ className: event.status === 'queued' ? 'ok' : 'failed', label: event.status })}</div><span class="text-secondary">${escapeHtml(event.sender)} -> ${escapeHtml((event.recipients || []).join(', '))}</span><span class="text-secondary">${escapeHtml(formatDate(event.createdAt))}</span></div>`).join('')}</div>`;
}

function renderSmtpBox(domain) {
  const submission = state.config?.submission;
  const credential = state.smtpCredential;
  const password = credential?.password || '';
  if (!submission?.enabled) return '<p class="text-secondary">SMTP Submission 未启用。</p>';
  return `
    <div class="smtp-grid">
      <div class="smtp-row"><span>Host</span><code>${escapeHtml(submission.host)}</code></div>
      <div class="smtp-row"><span>Ports</span>${(submission.ports || []).map((item) => `<code>${escapeHtml(item.port)} · ${escapeHtml(item.protocol)}</code>`).join('')}</div>
      <div class="smtp-row"><span>Username</span><div class="copy-row inline"><code>${escapeHtml(credential?.username || submission.username || '')}</code><button class="btn btn-sm btn-outline-secondary" data-copy="${escapeAttr(credential?.username || submission.username || '')}" type="button">复制</button></div></div>
      <div class="smtp-row"><span>Password</span>${password ? `<div class="copy-row inline"><code>${escapeHtml(password)}</code><button class="btn btn-sm btn-outline-secondary" data-copy="${escapeAttr(password)}" type="button">复制</button></div>` : '<p class="text-secondary">旧密码无法回显，请在 SMTP 页面重新设置一次新密码后复制。</p>'}</div>
      <div class="smtp-row"><span>AUTH</span><code>${submission.requireTlsForAuth ? '需要 TLS 后认证' : '允许明文认证'}</code></div>
      <div class="smtp-row"><span>From</span><code>noreply@${escapeHtml(domain.domain)}</code></div>
    </div>
  `;
}

function renderOptionalRecords(records) {
  if (!records.length) return '<p class="text-secondary">完成基础发信配置后可逐步启用。</p>';
  return renderRecordTable(records.map((record) => ({ ...record, status: 'idle' })));
}

function renderWarnings(warnings) {
  return `<ul class="warning-list">${warnings.map((warning) => `<li>${escapeHtml(warning)}</li>`).join('')}</ul>`;
}

function apiExample(domain) {
  const token = state.apiTokens[0] ? `${state.apiTokens[0].tokenPrefix}...` : '<USER_API_TOKEN>';
  return `curl -X POST ${state.config?.appBaseUrl || window.location.origin}/api/send \\
  -H 'Authorization: Bearer ${token}' \\
  -H 'Content-Type: application/json' \\
  -d '{
    "from": "noreply@${domain.domain}",
    "to": "user@example.com",
    "subject": "Hello from MailHub",
    "text": "Signed with DKIM and queued by MailHub."
  }'`;
}

async function addDomain(event) {
  event.preventDefault();
  await mutate(async () => {
    const data = Object.fromEntries(new FormData(event.target).entries());
    const result = await api('/api/domains', { method: 'POST', body: JSON.stringify(data) });
    state.domains.unshift(result.domain);
    state.selectedId = result.domain.id;
    event.target.reset();
    renderDefaults();
    render();
    await checkSelected();
  });
}

async function saveSmtpCredential(event) {
  event.preventDefault();
  await mutate(async () => {
    const data = Object.fromEntries(new FormData(event.target).entries());
    const result = await api('/api/smtp-credential', { method: 'PUT', body: JSON.stringify(data) });
    state.smtpCredential = result.credential;
    if (state.config?.submission) {
      state.config.submission.username = result.credential.username;
      state.config.submission.passwordSet = result.credential.passwordSet;
    }
    els.smtpPassword.value = '';
    renderDefaults();
    render();
    toast('SMTP 凭据已保存');
  });
}

async function saveDnsCredential(event) {
  event.preventDefault();
  await mutate(async () => {
    const data = Object.fromEntries(new FormData(event.target).entries());
    const id = Number(data.id || 0);
    delete data.id;
    const path = id ? `/api/dns-credentials/${id}` : '/api/dns-credentials';
    const method = id ? 'PATCH' : 'POST';
    const result = await api(path, { method, body: JSON.stringify(data) });
    if (id) {
      state.dnsCredentials = state.dnsCredentials.map((item) => item.id === id ? result.credential : item);
    } else {
      state.dnsCredentials.unshift(result.credential);
    }
    resetDnsCredentialForm();
    renderDefaults();
    render();
    toast(id ? 'DNS API 已更新' : 'DNS API 已新增');
  });
}

function editDnsCredential(id) {
  const credential = state.dnsCredentials.find((item) => item.id === id);
  if (!credential) return;
  setView('dns');
  resetDnsCredentialForm();
  els.dnsCredentialIdField.value = credential.id;
  els.dnsCredentialName.value = credential.name || '';
  els.dnsProvider.value = credential.provider || 'cloudflare';
  els.dnsZoneName.value = credential.zoneName || '';
  els.dnsDefaultTtl.value = credential.defaultTtl || 600;
  els.dnsCredentialFormTitle.textContent = `编辑 ${credential.name}`;
  els.dnsCredentialFormHint.textContent = '密钥字段留空会保留原值。';
  toggleDnsProviderFields();
  els.dnsCredentialName.focus();
}

function resetDnsCredentialForm() {
  els.dnsCredentialForm.reset();
  els.dnsCredentialIdField.value = '';
  els.dnsDefaultTtl.value = 600;
  els.dnsCredentialFormTitle.textContent = '新增 DNS API';
  els.dnsCredentialFormHint.textContent = '选择服务商后只填写对应字段。';
  toggleDnsProviderFields();
}

function toggleDnsProviderFields() {
  const provider = els.dnsProvider.value || 'cloudflare';
  for (const fieldset of document.querySelectorAll('[data-provider-field]')) {
    fieldset.classList.toggle('hidden', fieldset.dataset.providerField !== provider);
  }
}

async function createApiToken(event) {
  event.preventDefault();
  await mutate(async () => {
    const data = Object.fromEntries(new FormData(event.target).entries());
    const result = await api('/api/api-tokens', { method: 'POST', body: JSON.stringify(data) });
    state.apiTokens.unshift(result.token);
    event.target.reset();
    renderDefaults();
    render();
    await navigator.clipboard.writeText(result.token.token);
    toast('Token 已生成并复制，请立即保存');
  });
}

function generateSmtpPassword() {
  const bytes = new Uint8Array(24);
  crypto.getRandomValues(bytes);
  const password = btoa(String.fromCharCode(...bytes)).replace(/[+/=]/g, '').slice(0, 28);
  els.smtpPassword.type = 'text';
  els.smtpPassword.value = password;
  els.smtpPassword.focus();
  els.smtpPassword.select();
}

async function handleGlobalClick(event) {
  const viewButton = event.target.closest('[data-view]');
  if (viewButton && !event.target.closest('[data-domain-id]')) {
    event.preventDefault();
    setView(viewButton.dataset.view);
    render();
    return;
  }
  const copyButton = event.target.closest('[data-copy]');
  if (copyButton) {
    event.preventDefault();
    const value = copyButton.dataset.copy || '';
    if (!value) return;
    await navigator.clipboard.writeText(value);
    toast('已复制');
    return;
  }
  const actionTarget = event.target.closest('[data-action]');
  const action = actionTarget?.dataset.action;
  if (!action) return;
  const id = Number(actionTarget.closest('[data-id]')?.dataset.id || actionTarget.dataset.id || 0);
  if (action === 'check') return checkSelected();
  if (action === 'apply-dns') return applyDnsSelected();
  if (action === 'copy-all-dns') return copyAllDns();
  if (action === 'detail-tab') return selectDetailTab(actionTarget.dataset.tab);
  if (action === 'rotate-dkim') return rotateDkim();
  if (action === 'delete-domain') return deleteSelected();
  if (action === 'edit-dns') return editDnsCredential(id);
  if (action === 'test-dns') return testDnsCredential(id);
  if (action === 'delete-dns') return deleteDnsCredential(id);
  if (action === 'delete-token') return deleteApiToken(id);
  if (action === 'toggle-user') return toggleUser(id, actionTarget.closest('[data-status]')?.dataset.status);
}

async function handleDetailSubmit(event) {
  const form = event.target.closest('form[data-form]');
  if (!form) return;
  event.preventDefault();
  if (form.dataset.form === 'settings') return saveSettings(form);
  if (form.dataset.form === 'send') return sendTest(form);
  if (form.dataset.form === 'admin-settings') return saveAdminSettings(form);
}

function selectDetailTab(tab) {
  const allowed = ['dns', 'settings', 'send', 'integrations', 'events'];
  if (!allowed.includes(tab)) return;
  state.detailTab = tab;
  renderDetail();
}

async function checkSelected() {
  const id = state.selectedId;
  if (!id) return;
  await mutate(async () => {
    const result = await api(`/api/domains/${id}/check`, { method: 'POST' });
    replaceDomain(result.domain);
    render();
  });
}

async function applyDnsSelected() {
  const id = state.selectedId;
  if (!id) return;
  await mutate(async () => {
    const result = await api(`/api/domains/${id}/apply-dns`, { method: 'POST' });
    replaceDomain(result.domain);
    render();
    toast(result.apply?.ok ? 'DNS 配置完成' : 'DNS 配置部分失败');
  });
}

async function saveSettings(form) {
  const id = state.selectedId;
  const data = Object.fromEntries(new FormData(form).entries());
  await mutate(async () => {
    const result = await api(`/api/domains/${id}`, { method: 'PATCH', body: JSON.stringify(data) });
    replaceDomain(result.domain);
    render();
    await checkSelected();
  });
}

async function sendTest(form) {
  const id = state.selectedId;
  const data = Object.fromEntries(new FormData(form).entries());
  await mutate(async () => {
    await api(`/api/domains/${id}/test-send`, { method: 'POST', body: JSON.stringify(data) });
    const [events, analytics] = await Promise.all([
      api('/api/events'),
      api('/api/analytics?days=30')
    ]);
    state.events = events.events || [];
    state.analytics = analytics.analytics || state.analytics;
    renderDefaults();
    render();
    toast('已提交到发信队列');
  });
}

async function saveAdminSettings(form) {
  const data = Object.fromEntries(new FormData(form).entries());
  await mutate(async () => {
    const result = await api('/api/admin/settings', { method: 'PATCH', body: JSON.stringify(data) });
    state.settings = result.settings;
    state.config = { ...state.config, ...result.settings };
    renderDefaults();
    render();
    toast('系统设置已保存');
  });
}

async function rotateDkim() {
  const id = state.selectedId;
  if (!confirm('轮换 DKIM 后需要更新 DNS TXT 记录。继续？')) return;
  await mutate(async () => {
    const result = await api(`/api/domains/${id}/rotate-dkim`, { method: 'POST' });
    replaceDomain(result.domain);
    render();
    await checkSelected();
  });
}

async function deleteSelected() {
  const id = state.selectedId;
  const domain = state.domains.find((item) => item.id === id);
  if (!confirm(`删除 ${domain?.domain || '该域名'}？`)) return;
  await mutate(async () => {
    await api(`/api/domains/${id}`, { method: 'DELETE' });
    state.domains = state.domains.filter((item) => item.id !== id);
    state.selectedId = state.domains[0]?.id || null;
    renderDefaults();
    render();
  });
}

async function testDnsCredential(id) {
  await mutate(async () => {
    const result = await api(`/api/dns-credentials/${id}/test`, { method: 'POST' });
    state.dnsTestResults[id] = {
      ok: result.ok,
      message: result.ok ? `连接成功：${result.detail || providerLabel(result.provider)}` : (result.error || 'DNS API 连接失败')
    };
    renderDnsCredentials();
    toast(result.ok ? 'DNS API 连接成功' : result.error || 'DNS API 连接失败', result.ok ? 'info' : 'error');
  });
}

async function deleteDnsCredential(id) {
  const credential = state.dnsCredentials.find((item) => item.id === id);
  if (!confirm(`删除 ${credential?.name || '该 DNS API 凭据'}？`)) return;
  await mutate(async () => {
    await api(`/api/dns-credentials/${id}`, { method: 'DELETE' });
    state.dnsCredentials = state.dnsCredentials.filter((item) => item.id !== id);
    state.domains = state.domains.map((domain) => domain.dnsCredentialId === id ? { ...domain, dnsCredentialId: null } : domain);
    if (Number(els.dnsCredentialIdField.value || 0) === id) resetDnsCredentialForm();
    renderDefaults();
    render();
  });
}

async function deleteApiToken(id) {
  if (!confirm('删除该 API Token？')) return;
  await mutate(async () => {
    await api(`/api/api-tokens/${id}`, { method: 'DELETE' });
    state.apiTokens = state.apiTokens.filter((item) => item.id !== id);
    renderDefaults();
    render();
  });
}

async function toggleUser(id, status) {
  const next = status === 'active' ? 'disabled' : 'active';
  await mutate(async () => {
    const result = await api(`/api/admin/users/${id}`, { method: 'PATCH', body: JSON.stringify({ status: next }) });
    state.users = state.users.map((user) => user.id === id ? result.user : user);
    renderDefaults();
  });
}

async function copyAllDns() {
  const domain = state.domains.find((item) => item.id === state.selectedId);
  const records = domain?.status?.records || [];
  if (!records.length) return toast('暂无 DNS 记录');
  const text = records.map((record) => `${record.host}\t${record.type}\t${record.value || ''}`).join('\n');
  await navigator.clipboard.writeText(text);
  toast('已复制全部 DNS 记录');
}

async function logout() {
  setBusy(true);
  try {
    await fetch('/api/logout', { method: 'POST' });
  } finally {
    window.location.href = '/login';
  }
}

async function mutate(fn) {
  setBusy(true);
  try {
    await fn();
  } catch (error) {
    toast(error.message, 'error');
  } finally {
    setBusy(false);
  }
}

async function api(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    headers: { 'Content-Type': 'application/json', ...(options.headers || {}) }
  });
  const text = await response.text();
  const payload = text ? JSON.parse(text) : {};
  if (!response.ok) {
    if (response.status === 401) {
      window.location.href = '/login';
      return {};
    }
    throw new Error(payload.error || `HTTP ${response.status}`);
  }
  return payload;
}

function replaceDomain(domain) {
  state.domains = state.domains.map((item) => item.id === domain.id ? domain : item);
}

function statusLabel(status) {
  return {
    queued: '成功入队',
    failed: '发送失败'
  }[status] || status || 'unknown';
}

function statusMeta(target) {
  if (!target || (!target.checkedAt && !target.status)) return { className: 'idle', label: '未检查' };
  if (target.verified || target.status === 'ok') return { className: 'ok', label: '通过' };
  if (target.status === 'pending') return { className: 'pending', label: '传播中' };
  if (target.status === 'missing') return { className: 'missing', label: '缺失' };
  if (target.status === 'warn') return { className: 'warn', label: '需调整' };
  return { className: 'warn', label: '待配置' };
}

function badge(meta) {
  return `<span class="badge ${badgeTone(meta.className)}">${escapeHtml(meta.label)}</span>`;
}

function badgeTone(className) {
  return {
    ok: 'bg-green-lt',
    pending: 'bg-blue-lt',
    warn: 'bg-yellow-lt',
    missing: 'bg-red-lt',
    failed: 'bg-red-lt',
    idle: 'bg-secondary-lt'
  }[className] || 'bg-secondary-lt';
}

function providerLabel(provider) {
  return { cloudflare: 'Cloudflare', aliyun: '阿里云 DNS', dnspod: '腾讯云 DNSPod' }[provider] || provider;
}

function setBusy(value) {
  state.busy = value;
  document.body.classList.toggle('busy', value);
  els.refreshButton.disabled = value;
  if (els.refreshButtonMobile) els.refreshButtonMobile.disabled = value;
}

function toast(message, tone = 'info') {
  const node = document.createElement('div');
  node.className = `app-toast ${tone}`;
  node.textContent = message;
  els.toastHost.appendChild(node);
  setTimeout(() => node.remove(), 3200);
}

function formatDate(value) {
  if (!value) return '';
  return new Intl.DateTimeFormat('zh-CN', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' }).format(new Date(value));
}

function escapeHtml(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function escapeAttr(value) {
  return escapeHtml(value).replace(/`/g, '&#096;');
}
