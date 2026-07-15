import assert from 'node:assert/strict';
import { test } from 'node:test';

import { parseInboundMessage } from '../src/inbound-mail.js';

test('parseInboundMessage extracts common headers and text bodies from MIME', async () => {
  const rawMessage = [
    'From: Alice <alice@example.net>',
    'To: Support <support@inbound.example>',
    'Subject: =?UTF-8?B?5pS25L+h5rWL6K+V?=',
    'Message-ID: <mime-test@example.net>',
    'MIME-Version: 1.0',
    'Content-Type: multipart/alternative; boundary="alt"',
    '',
    '--alt',
    'Content-Type: text/plain; charset=UTF-8',
    'Content-Transfer-Encoding: base64',
    '',
    Buffer.from('Hello plain body.', 'utf8').toString('base64'),
    '--alt',
    'Content-Type: text/html; charset=UTF-8',
    'Content-Transfer-Encoding: quoted-printable',
    '',
    '<p>Hello <strong>HTML</strong> body.</p>',
    '--alt--',
    ''
  ].join('\r\n');

  const parsed = await parseInboundMessage(rawMessage, ['support@inbound.example']);

  assert.equal(parsed.sender, 'alice@example.net');
  assert.deepEqual(parsed.recipients, ['support@inbound.example']);
  assert.equal(parsed.subject, '收信测试');
  assert.equal(parsed.messageId, '<mime-test@example.net>');
  assert.equal(parsed.textBody, 'Hello plain body.');
  assert.match(parsed.htmlBody, /<strong>HTML<\/strong>/);
  assert.equal(parsed.preview, 'Hello plain body.');
});
