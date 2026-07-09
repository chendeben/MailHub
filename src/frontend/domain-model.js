const REQUIRED_DNS_KEYS = ['verification', 'dkim', 'spf', 'dmarc', 'sender-a'];

const STATUS_META = {
  ok: { key: 'success', label: '已通过', color: 'success' },
  verified: { key: 'success', label: '已通过', color: 'success' },
  pending: { key: 'pending', label: '等待生效', color: 'warning' },
  warn: { key: 'error', label: '配置错误', color: 'error' },
  failed: { key: 'error', label: '配置错误', color: 'error' },
  error: { key: 'error', label: '配置错误', color: 'error' },
  missing: { key: 'idle', label: '未配置', color: 'default' },
  idle: { key: 'idle', label: '未配置', color: 'default' }
};

export function getRecordStatusMeta(record = {}) {
  return STATUS_META[String(record.status || '').toLowerCase()] || STATUS_META.missing;
}

export function getDnsCurrentValues(record = {}) {
  if (Array.isArray(record.current)) return record.current.filter((value) => value);
  if (record.current) return [record.current];
  const status = getRecordStatusMeta(record);
  return status.key === 'success' && record.value ? [record.value] : [];
}

export function getRequiredDnsRecords(domain = {}) {
  const records = Array.isArray(domain.status?.records) ? domain.status.records : [];
  const byKey = new Map(records.map((record) => [record.key, record]));
  return REQUIRED_DNS_KEYS.map((key) => byKey.get(key)).filter(Boolean);
}

export function getVisibleDnsRecords(records = []) {
  const rank = new Map(REQUIRED_DNS_KEYS.map((key, index) => [key, index]));
  return [...records]
    .filter((record) => rank.has(record.key))
    .sort((a, b) => rank.get(a.key) - rank.get(b.key));
}

export function buildDomainHealth(domain = {}) {
  const records = getRequiredDnsRecords(domain);
  const total = REQUIRED_DNS_KEYS.length;
  const passed = records.filter((record) => getRecordStatusMeta(record).key === 'success').length;
  const dnsIssues = records.filter((record) => {
    const key = getRecordStatusMeta(record).key;
    return key === 'error' || key === 'idle';
  }).length
    + Math.max(0, total - records.length);
  const percent = total ? Math.round((passed / total) * 100) : 0;
  const status = dnsIssues > 0 ? 'error' : (passed === total ? 'success' : 'warning');

  return {
    status,
    label: status === 'success' ? '健康' : (status === 'warning' ? '等待 DNS 生效' : '需要处理'),
    passed,
    total,
    percent,
    dnsIssues,
    checkedAt: domain.status?.checkedAt || ''
  };
}

export function isDomainVerified(domain = {}) {
  return Boolean(domain.status?.verified) || buildDomainHealth(domain).status === 'success';
}

export function buildDnsApplyFeedback(apply, messages = {}) {
  const completed = messages.completed || 'DNS 写入请求已完成';
  const partial = messages.partial || 'DNS 写入部分失败';
  if (!apply || apply.ok) return { type: 'success', message: completed };

  const failed = Array.isArray(apply.results) ? apply.results.filter((result) => !result.ok) : [];
  const firstError = failed.find((result) => result.error)?.error || '';
  return {
    type: 'warning',
    message: firstError ? `${partial}：${firstError}` : partial
  };
}

export function getDnsRecordOrder() {
  return [...REQUIRED_DNS_KEYS];
}
