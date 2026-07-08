import { buildDomainHealth } from './domain-model.js';

/**
 * @param {{
 *   analytics?: any;
 *   domains?: any[];
 *   events?: any[];
 *   config?: any;
 *   smtpCredential?: any;
 * }} [input]
 */
export function buildDashboardSummary({
  analytics = null,
  domains = [],
  events = [],
  config = null,
  smtpCredential = null
} = {}) {
  const summary = analytics?.summary || {};
  const total = Number(summary.total || 0);
  const failed = Number(summary.failed || 0);
  const verifiedDomains = summary.verifiedDomains ?? domains.filter((domain) => domain.status?.verified).length;
  const dnsIssues = domains.reduce((count, domain) => count + buildDomainHealth(domain).dnsIssues, 0);

  return {
    verifiedDomains,
    today: Number(summary.today || 0),
    successRate: Number(summary.successRate || 0),
    bounceRate: total ? Math.round((failed / total) * 1000) / 10 : 0,
    complaintRate: Number(summary.complaintRate || 0),
    lastSentAt: events[0]?.createdAt || '',
    dnsIssues,
    smtpReady: Boolean(config?.submission?.enabled && smtpCredential?.passwordSet)
  };
}

/**
 * @param {any} [analytics]
 * @returns {Array<{date: string; total: number; accepted: number; failed: number; recipients: number}>}
 */
export function buildTrendSeries(analytics = null) {
  return (analytics?.byDay || []).map((item) => ({
    date: item.date || item.day,
    total: Number(item.total || 0),
    accepted: Number(item.queued || 0),
    failed: Number(item.failed || 0),
    recipients: Number(item.recipients || 0)
  }));
}

/**
 * @param {any} [analytics]
 * @returns {Array<{status: string; label: string; value: number}>}
 */
export function buildStatusDistribution(analytics = null) {
  return (analytics?.byStatus || []).map((item) => ({
    status: item.status || 'unknown',
    label: item.status || 'unknown',
    value: Number(item.total || 0)
  }));
}

/**
 * @param {any} [analytics]
 * @returns {Array<{domain: string; total: number; accepted: number; failed: number; recipients: number}>}
 */
export function buildDomainRanking(analytics = null) {
  return [...(analytics?.byDomain || [])]
    .sort((a, b) => Number(b.total || 0) - Number(a.total || 0))
    .map((item) => ({
      domain: item.domain || 'unknown',
      total: Number(item.total || 0),
      accepted: Number(item.queued || 0),
      failed: Number(item.failed || 0),
      recipients: Number(item.recipients || 0)
    }));
}

/**
 * @param {any} [analytics]
 * @returns {Array<{hour: string; total: number; accepted: number; failed: number}>}
 */
export function buildHourlyHeatmap(analytics = null) {
  return (analytics?.hourly || []).map((item) => ({
    hour: `${String(Number(item.hour || 0)).padStart(2, '0')}:00`,
    total: Number(item.total || 0),
    accepted: Number(item.queued || 0),
    failed: Number(item.failed || 0)
  }));
}
