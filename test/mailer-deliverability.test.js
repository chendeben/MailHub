import assert from 'node:assert/strict';
import { test } from 'node:test';

import {
  buildDeliverabilityHeaders,
  buildMessage,
  createFeedbackId
} from '../src/mailer.js';

test('builds optional deliverability headers without unsafe header injection', () => {
  const headers = buildDeliverabilityHeaders({
    from: 'sender@example.com',
    listUnsubscribeMailto: 'unsubscribe@example.com',
    listUnsubscribeUrl: 'https://example.com/unsubscribe/{eventId}?r={recipient}',
    listUnsubscribePostEnabled: true,
    feedbackId: 'mh.u1.d2.e3:MailHub',
    reportAbuseTo: 'abuse@example.com\r\nX-Bad: yes',
    csaComplaintsTo: 'csa@example.com',
    context: {
      eventId: 42,
      recipient: 'reader@example.net'
    }
  });

  assert.deepEqual(headers, [
    ['List-Unsubscribe', '<mailto:unsubscribe@example.com>, <https://example.com/unsubscribe/42?r=reader%40example.net>'],
    ['List-Unsubscribe-Post', 'List-Unsubscribe=One-Click'],
    ['Feedback-Id', 'mh.u1.d2.e3:MailHub'],
    ['X-Report-Abuse-To', 'abuse@example.com X-Bad: yes'],
    ['X-CSA-Complaints', 'csa@example.com'],
    ['X-Sender', 'sender@example.com']
  ]);

  const raw = buildMessage({
    from: 'sender@example.com',
    to: 'reader@example.net',
    subject: 'Deliverability',
    text: 'hello',
    headers
  });

  assert.match(raw, /^List-Unsubscribe: <mailto:unsubscribe@example\.com>,\r\n <https:\/\/example\.com\/unsubscribe\/42\?r=reader%40example\.net>$/m);
  assert.match(raw, /^List-Unsubscribe-Post: List-Unsubscribe=One-Click$/m);
  assert.match(raw, /^Feedback-Id: mh\.u1\.d2\.e3:MailHub$/m);
  assert.match(raw, /^X-Report-Abuse-To: abuse@example\.com X-Bad: yes$/m);
  assert.doesNotMatch(raw, /^X-Bad:/m);
});

test('folds long deliverability headers and only adds one-click for HTTPS URLs', () => {
  const headers = buildDeliverabilityHeaders({
    from: 'sender@example.com',
    listUnsubscribeMailto: 'unsubscribe@example.com',
    listUnsubscribeUrl: 'http://example.com/unsubscribe/{eventId}',
    listUnsubscribePostEnabled: true,
    context: { eventId: 42 }
  });

  assert.deepEqual(headers, [
    ['List-Unsubscribe', '<mailto:unsubscribe@example.com>, <http://example.com/unsubscribe/42>'],
    ['X-Sender', 'sender@example.com']
  ]);

  const longHeaders = buildDeliverabilityHeaders({
    from: 'sender@example.com',
    listUnsubscribeMailto: 'unsubscribe@example.com',
    listUnsubscribeUrl: `https://example.com/u/${'x'.repeat(35)}`,
    listUnsubscribePostEnabled: true
  });
  const raw = buildMessage({
    from: 'sender@example.com',
    to: 'reader@example.net',
    subject: 'Long header',
    text: 'hello',
    headers: longHeaders
  });

  assert.match(raw, /^List-Unsubscribe: <mailto:unsubscribe@example\.com>,\r\n <https:\/\/example\.com\/u\/x+/m);
  assert.match(raw, /\r\n <https:\/\/example\.com\/u\/x+>\r\nList-Unsubscribe-Post:/);
  for (const line of raw.split('\r\n')) {
    if (/^(List-Unsubscribe:| )/.test(line)) assert.ok(line.length <= 78, line);
  }
});

test('creates stable opaque Feedback-Id values', () => {
  const first = createFeedbackId({
    userId: 7,
    domainId: 9,
    eventId: 11,
    secret: 'feedback-secret'
  });
  const second = createFeedbackId({
    userId: 7,
    domainId: 9,
    eventId: 11,
    secret: 'feedback-secret'
  });
  const different = createFeedbackId({
    userId: 7,
    domainId: 9,
    eventId: 12,
    secret: 'feedback-secret'
  });

  assert.equal(first, second);
  assert.notEqual(first, different);
  assert.match(first, /^mh\.[a-f0-9]{12}\.[a-f0-9]{12}\.[a-f0-9]{12}:MailHub$/);
});
