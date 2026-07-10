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
 * @returns {Array<{stage: string; total: number; rate: number; tone: 'success' | 'warning' | 'error' | 'info' | 'neutral'}>}
 */
export function buildDeliveryFunnel(analytics = null) {
  return (analytics?.deliveryFunnel || []).map((item) => {
    const stage = item.stage || 'unknown';
    return {
      stage,
      total: Number(item.total || 0),
      rate: Number(item.rate || 0),
      tone: deliveryStageTone(stage)
    };
  });
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

/**
 * @param {any} [event]
 * @returns {Array<{
 *   stage: string;
 *   at: string;
 *   tone: 'success' | 'warning' | 'error' | 'info' | 'neutral';
 *   status?: string;
 *   queueId?: string;
 *   recipient?: string;
 *   relay?: string;
 *   response?: string;
 *   webhookId?: number;
 *   responseStatus?: number | null;
 * }>}
 */
export function buildEventTimeline(event = null) {
  if (!event) return [];
  const timeline = [];
  if (event.createdAt) {
    timeline.push({
      stage: 'submitted',
      at: event.createdAt,
      tone: 'info',
      status: event.status
    });
  }
  if (event.queueId) {
    timeline.push({
      stage: 'accepted',
      at: event.createdAt || '',
      tone: 'info',
      status: 'queued',
      queueId: event.queueId
    });
  }
  const attempts = Array.isArray(event.deliveryAttempts) ? event.deliveryAttempts : [];
  for (const attempt of attempts) {
    const stage = deliveryAttemptStage(attempt.status);
    timeline.push({
      stage,
      at: attempt.at || '',
      tone: deliveryStageTone(stage),
      status: attempt.status,
      queueId: attempt.queueId,
      recipient: attempt.recipient,
      relay: attempt.relay,
      response: attempt.response
    });
  }
  if (!attempts.length && event.deliveredAt) {
    timeline.push({
      stage: 'delivered',
      at: event.deliveredAt,
      tone: 'success',
      status: 'sent',
      queueId: event.queueId
    });
  }
  const webhookDeliveries = Array.isArray(event.webhookDeliveries) ? event.webhookDeliveries : [];
  for (const delivery of webhookDeliveries) {
    timeline.push({
      stage: 'webhook',
      at: delivery.lastAttemptAt || delivery.createdAt || '',
      tone: webhookDeliveryTone(delivery.status),
      status: delivery.status,
      webhookId: delivery.webhookId,
      responseStatus: delivery.responseStatus
    });
  }
  return timeline;
}

function deliveryAttemptStage(status) {
  if (status === 'sent') return 'delivered';
  if (status === 'deferred') return 'pending';
  if (status === 'bounced' || status === 'failed') return 'failed';
  return 'pending';
}

function deliveryStageTone(stage) {
  if (stage === 'delivered') return 'success';
  if (stage === 'pending') return 'warning';
  if (stage === 'failed') return 'error';
  if (stage === 'submitted' || stage === 'accepted') return 'info';
  return 'neutral';
}

function webhookDeliveryTone(status) {
  if (status === 'success') return 'success';
  if (status === 'dead') return 'error';
  if (status === 'pending' || status === 'processing') return 'warning';
  return 'neutral';
}
