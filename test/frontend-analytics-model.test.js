import assert from 'node:assert/strict';
import { test } from 'node:test';

import {
  buildDashboardSummary,
  buildDeliveryFunnel,
  buildEngagementSummary,
  buildEngagementTrend,
  buildEventTimeline,
  buildDomainRanking,
  buildHourlyHeatmap,
  buildStatusDistribution,
  buildTopLinks,
  buildTrendSeries
} from '../src/frontend/analytics-model.js';

test('builds dashboard summary from analytics, DNS health, and SMTP state', () => {
  const summary = buildDashboardSummary({
    analytics: {
      summary: {
        total: 20,
        queued: 18,
        failed: 2,
        recipients: 25,
        today: 8,
        successRate: 90,
        verifiedDomains: 1
      }
    },
    domains: [
      domain(true, [
        record('verification', 'ok'),
        record('dkim', 'ok'),
        record('spf', 'ok'),
        record('dmarc', 'ok'),
        record('sender-a', 'ok')
      ]),
      domain(false, [
        record('verification', 'ok'),
        record('dkim', 'warn'),
        record('spf', 'missing')
      ])
    ],
    events: [{ createdAt: '2026-07-08T12:30:00.000Z' }],
    config: { submission: { enabled: true } },
    smtpCredential: { passwordSet: true }
  });

  assert.equal(summary.verifiedDomains, 1);
  assert.equal(summary.today, 8);
  assert.equal(summary.successRate, 90);
  assert.equal(summary.bounceRate, 10);
  assert.equal(summary.complaintRate, 0);
  assert.equal(summary.dnsIssues, 4);
  assert.equal(summary.smtpReady, true);
  assert.equal(summary.lastSentAt, '2026-07-08T12:30:00.000Z');
});

test('normalizes chart datasets for trend, status, ranking, and hourly views', () => {
  const analytics = {
    byDay: [
      { day: '2026-07-07', total: 6, queued: 5, failed: 1, recipients: 8 },
      { day: '2026-07-08', total: 9, queued: 9, failed: 0, recipients: 10 }
    ],
    byStatus: [
      { status: 'queued', total: 14 },
      { status: 'failed', total: 1 }
    ],
    byDomain: [
      { domain: 'b.example.com', total: 2, queued: 2, failed: 0, recipients: 2 },
      { domain: 'a.example.com', total: 8, queued: 7, failed: 1, recipients: 12 }
    ],
    hourly: [
      { hour: 0, total: 0, queued: 0, failed: 0 },
      { hour: 9, total: 4, queued: 3, failed: 1 }
    ]
  };

  assert.deepEqual(buildTrendSeries(analytics), [
    { date: '2026-07-07', total: 6, accepted: 5, failed: 1, recipients: 8 },
    { date: '2026-07-08', total: 9, accepted: 9, failed: 0, recipients: 10 }
  ]);
  assert.deepEqual(buildStatusDistribution(analytics), [
    { status: 'queued', label: 'queued', value: 14 },
    { status: 'failed', label: 'failed', value: 1 }
  ]);
  assert.deepEqual(buildDomainRanking(analytics).map((item) => item.domain), ['a.example.com', 'b.example.com']);
  assert.deepEqual(buildHourlyHeatmap(analytics).find((item) => item.hour === '09:00'), {
    hour: '09:00',
    total: 4,
    accepted: 3,
    failed: 1
  });
});

test('builds delivery funnel and event timeline models', () => {
  const analytics = {
    deliveryFunnel: [
      { stage: 'submitted', total: 5, rate: 100 },
      { stage: 'accepted', total: 4, rate: 80 },
      { stage: 'delivered', total: 2, rate: 40 },
      { stage: 'pending', total: 1, rate: 20 },
      { stage: 'failed', total: 2, rate: 40 }
    ]
  };

  assert.deepEqual(buildDeliveryFunnel(analytics), [
    { stage: 'submitted', total: 5, rate: 100, tone: 'info' },
    { stage: 'accepted', total: 4, rate: 80, tone: 'info' },
    { stage: 'delivered', total: 2, rate: 40, tone: 'success' },
    { stage: 'pending', total: 1, rate: 20, tone: 'warning' },
    { stage: 'failed', total: 2, rate: 40, tone: 'error' }
  ]);

  const timeline = buildEventTimeline({
    id: 7,
    status: 'sent',
    queueId: 'Q7',
    createdAt: '2026-07-09T11:59:00.000Z',
    deliveredAt: '2026-07-09T12:00:00.000Z',
    deliveryAttempts: [{
      at: '2026-07-09T12:00:00.000Z',
      queueId: 'Q7',
      status: 'sent',
      recipient: 'user@example.com',
      relay: 'mx.example.net',
      response: '250 ok'
    }],
    webhookDeliveries: [{
      id: 11,
      webhookId: 3,
      userId: 1,
      sendEventId: 7,
      eventType: 'sent',
      status: 'success',
      attemptCount: 1,
      createdAt: '2026-07-09T12:00:01.000Z',
      lastAttemptAt: '2026-07-09T12:00:02.000Z',
      responseStatus: 200
    }]
  });

  assert.deepEqual(timeline.map((item) => item.stage), ['submitted', 'accepted', 'delivered', 'webhook']);
  assert.equal(timeline[1].queueId, 'Q7');
  assert.equal(timeline[2].tone, 'success');
  assert.equal(timeline[3].status, 'success');
});

test('normalizes engagement KPIs trends links and timeline events', () => {
  const analytics = {
    engagement: {
      trackedDelivered: 10,
      totalOpens: 8,
      uniqueOpens: 6,
      proxyOpens: 2,
      totalClicks: 5,
      uniqueClicks: 4,
      scannerEvents: 3,
      openRate: 60,
      clickRate: 40,
      clickToOpenRate: 66.7
    },
    engagementByDay: [
      { day: '2026-07-08', opens: 3, uniqueOpens: 2, clicks: 1, uniqueClicks: 1, scannerEvents: 1 },
      { day: '2026-07-09', opens: 5, uniqueOpens: 4, clicks: 4, uniqueClicks: 3, scannerEvents: 2 }
    ],
    topLinks: [{
      fingerprint: 'abc',
      target: 'https://example.com/path',
      targetOrigin: 'https://example.com',
      clicks: 5,
      uniqueClicks: 4,
      lastClickedAt: '2026-07-09T12:00:00.000Z'
    }]
  };

  assert.deepEqual(buildEngagementSummary(analytics), analytics.engagement);
  assert.deepEqual(buildEngagementTrend(analytics)[0], {
    date: '2026-07-08',
    opens: 3,
    uniqueOpens: 2,
    clicks: 1,
    uniqueClicks: 1,
    scannerEvents: 1
  });
  assert.equal(buildTopLinks(analytics)[0].target, 'https://example.com/path');

  const timeline = buildEventTimeline({
    id: 9,
    status: 'sent',
    createdAt: '2026-07-09T11:00:00.000Z',
    deliveryAttempts: [{
      at: '2026-07-09T12:02:00.000Z',
      status: 'sent',
      recipient: 'user@example.com',
      response: '250 ok'
    }],
    tracking: {
      events: [
        { id: 1, eventType: 'open', source: 'proxy', occurredAt: '2026-07-09T12:00:00.000Z' },
        {
          id: 2,
          eventType: 'click',
          source: 'direct',
          targetOrigin: 'https://example.com',
          occurredAt: '2026-07-09T12:01:00.000Z'
        }
      ]
    }
  });
  assert.deepEqual(timeline.map((item) => item.stage), ['submitted', 'opened', 'clicked', 'delivered']);
  assert.equal(timeline[1].source, 'proxy');
  assert.equal(timeline[2].targetOrigin, 'https://example.com');
});

function domain(verified, records) {
  return {
    status: {
      verified,
      records
    }
  };
}

function record(key, status) {
  return { key, status };
}
