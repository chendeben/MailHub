import assert from 'node:assert/strict';
import { test } from 'node:test';

import {
  buildDashboardSummary,
  buildDomainRanking,
  buildHourlyHeatmap,
  buildStatusDistribution,
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
