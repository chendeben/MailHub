import assert from 'node:assert/strict';
import { test } from 'node:test';

import {
  classifyTrackingSource,
  createTrackingToken,
  decryptTrackingTarget,
  encryptTrackingTarget,
  hashTrackingClientIp,
  hashTrackingToken,
  instrumentHtml,
  instrumentRawMime,
  normalizeTrackingTarget,
  stripRawMimeHeaders,
  trackingTargetFingerprint,
  trackingReplayKey
} from '../src/tracking.js';

test('generates opaque tokens and stable hashes', () => {
  const token = createTrackingToken();
  assert.match(token, /^[A-Za-z0-9_-]{43}$/);
  assert.match(hashTrackingToken(token), /^[a-f0-9]{64}$/);
  assert.equal(hashTrackingToken(token), hashTrackingToken(token));
  assert.notEqual(hashTrackingToken(token), hashTrackingToken(createTrackingToken()));
});

test('encrypts destinations with authenticated random nonces', () => {
  const target = 'https://example.com/reset?token=secret#account';
  const first = encryptTrackingTarget(target, 'tracking-secret');
  const second = encryptTrackingTarget(target, 'tracking-secret');

  assert.notEqual(first, second);
  assert.equal(first.includes('secret'), false);
  assert.equal(decryptTrackingTarget(first, 'tracking-secret'), target);
  assert.throws(() => decryptTrackingTarget(`${first.slice(0, -1)}x`, 'tracking-secret'));
  assert.throws(() => decryptTrackingTarget(first, 'different-secret'));
  assert.equal(trackingTargetFingerprint(target, 'tracking-secret'), trackingTargetFingerprint(target, 'tracking-secret'));
  assert.notEqual(trackingTargetFingerprint(target, 'tracking-secret'), trackingTargetFingerprint(target, 'different-secret'));
});

test('accepts absolute http destinations and rejects unsafe protocols', () => {
  assert.equal(normalizeTrackingTarget('https://Example.com:443/path?q=1#x'), 'https://example.com/path?q=1#x');
  assert.equal(normalizeTrackingTarget('http://example.com/a'), 'http://example.com/a');
  assert.throws(() => normalizeTrackingTarget('javascript:alert(1)'), /http/i);
  assert.throws(() => normalizeTrackingTarget('mailto:user@example.com'), /http/i);
  assert.throws(() => normalizeTrackingTarget('/relative'), /absolute/i);
});

test('scopes IP hashes to account message and UTC day', () => {
  const input = {
    ip: '203.0.113.7',
    secret: 'tracking-secret',
    userId: 1,
    sendEventId: 10,
    occurredAt: '2026-07-09T23:59:00.000Z'
  };
  const hash = hashTrackingClientIp(input);
  assert.equal(hash, hashTrackingClientIp(input));
  assert.notEqual(hash, hashTrackingClientIp({ ...input, userId: 2 }));
  assert.notEqual(hash, hashTrackingClientIp({ ...input, sendEventId: 11 }));
  assert.notEqual(hash, hashTrackingClientIp({ ...input, occurredAt: '2026-07-10T00:00:00.000Z' }));
});

test('classifies direct proxy and scanner clients', () => {
  assert.equal(classifyTrackingSource('Mozilla/5.0 AppleWebKit/537.36 Chrome/126 Safari/537.36'), 'direct');
  assert.equal(classifyTrackingSource('Mozilla/5.0 (via ggpht.com GoogleImageProxy)'), 'proxy');
  assert.equal(classifyTrackingSource('Barracuda Sentinel Link Scanner'), 'scanner');
  assert.equal(classifyTrackingSource('curl/8.7.1'), 'scanner');
});

test('builds minute-bucket replay keys from event and client context', () => {
  const input = {
    secret: 'tracking-secret',
    sendEventId: 10,
    eventType: 'click',
    trackingLinkId: 4,
    ipHash: 'ip-hash',
    userAgent: 'Mozilla/5.0',
    occurredAt: '2026-07-09T12:34:05.000Z'
  };
  const key = trackingReplayKey(input);
  assert.equal(key, trackingReplayKey({ ...input, occurredAt: '2026-07-09T12:34:59.999Z' }));
  assert.notEqual(key, trackingReplayKey({ ...input, occurredAt: '2026-07-09T12:35:00.000Z' }));
  assert.notEqual(key, trackingReplayKey({ ...input, trackingLinkId: 5 }));
});

test('rewrites absolute links and appends exactly one open pixel', () => {
  const createdTargets = [];
  const result = instrumentHtml(
    '<html><body><a href="https://example.com/reset?token=secret">Reset</a><p>Hello</p></body></html>',
    {
      openPixelUrl: 'https://mail.example/t/o/open-token.gif',
      createClickUrl(target) {
        createdTargets.push(target);
        return 'https://mail.example/t/c/click-token';
      }
    }
  );

  assert.deepEqual(createdTargets, ['https://example.com/reset?token=secret']);
  assert.match(result.html, /href="https:\/\/mail\.example\/t\/c\/click-token"/);
  assert.equal((result.html.match(/data-mailhub-open/g) || []).length, 1);
  assert.match(result.html, /src="https:\/\/mail\.example\/t\/o\/open-token\.gif"/);
  assert.equal(result.linkCount, 1);
  assert.equal(result.pixelAdded, true);
});

test('skips opt-out and non-http links without duplicating an existing pixel', () => {
  let calls = 0;
  const result = instrumentHtml(
    '<a data-mailhub-no-track href="https://example.com/private">Private</a>' +
      '<a href="mailto:user@example.com">Mail</a>' +
      '<a href="/relative">Relative</a>' +
      '<img data-mailhub-open="true" src="https://mail.example/t/o/token.gif">',
    {
      openPixelUrl: 'https://mail.example/t/o/token.gif',
      createClickUrl() {
        calls += 1;
        return 'https://mail.example/t/c/token';
      }
    }
  );

  assert.equal(calls, 0);
  assert.equal(result.linkCount, 0);
  assert.equal(result.pixelAdded, false);
  assert.equal((result.html.match(/data-mailhub-open/g) || []).length, 1);
});

test('rewrites encoded HTML MIME parts and preserves attachments', async () => {
  const html = '<html><body><a href="https://example.com/a">A</a></body></html>';
  const attachment = Buffer.from('attachment-bytes').toString('base64');
  const raw = [
    'From: sender@example.com',
    'To: user@example.net',
    'Subject: Tracked',
    'MIME-Version: 1.0',
    'Content-Type: multipart/mixed; boundary="outer"',
    '',
    '--outer',
    'Content-Type: text/html; charset=UTF-8',
    'Content-Transfer-Encoding: base64',
    '',
    Buffer.from(html).toString('base64'),
    '--outer',
    'Content-Type: application/octet-stream',
    'Content-Disposition: attachment; filename="file.bin"',
    'Content-Transfer-Encoding: base64',
    '',
    attachment,
    '--outer--',
    ''
  ].join('\r\n');

  const result = await instrumentRawMime(raw, {
    openPixelUrl: 'https://mail.example/t/o/open.gif',
    createClickUrl: () => 'https://mail.example/t/c/click'
  });

  assert.equal(result.tracked, true);
  assert.equal(result.linkCount, 1);
  assert.match(result.rawMessage, /filename="file\.bin"/);
  assert.match(result.rawMessage, new RegExp(attachment));
  const encodedHtml = result.rawMessage.match(/Content-Type: text\/html[^]*?\r\n\r\n([A-Za-z0-9+/=\r\n]+?)\r\n--outer/i)?.[1] || '';
  const decodedHtml = Buffer.from(encodedHtml.replace(/\s+/g, ''), 'base64').toString('utf8');
  assert.match(decodedHtml, /mail\.example\/t\/c\/click/);
  assert.match(decodedHtml, /data-mailhub-open/);
});

test('skips signed encrypted and existing-DKIM raw messages', async () => {
  const messages = [
    'DKIM-Signature: v=1; d=example.com; b=x\r\nContent-Type: text/html\r\n\r\n<a href="https://example.com">A</a>\r\n',
    'Content-Type: multipart/signed; boundary="s"\r\n\r\n--s--\r\n',
    'Content-Type: application/pkcs7-mime\r\n\r\nencrypted\r\n'
  ];
  for (const raw of messages) {
    const result = await instrumentRawMime(raw, {
      openPixelUrl: 'https://mail.example/t/o/open.gif',
      createClickUrl: () => 'https://mail.example/t/c/click'
    });
    assert.equal(result.tracked, false);
    assert.equal(result.rawMessage, raw);
    assert.ok(result.skippedReason);
  }
});

test('does not rewrite HTML nested inside signed MIME content', async () => {
  const raw = [
    'From: sender@example.com',
    'To: user@example.net',
    'MIME-Version: 1.0',
    'Content-Type: multipart/mixed; boundary="outer"',
    '',
    '--outer',
    'Content-Type: multipart/signed; boundary="signed"; protocol="application/pgp-signature"',
    '',
    '--signed',
    'Content-Type: text/html; charset=UTF-8',
    '',
    '<a href="https://example.com/signed">Signed</a>',
    '--signed',
    'Content-Type: application/pgp-signature',
    '',
    'signature-bytes',
    '--signed--',
    '--outer--',
    ''
  ].join('\r\n');

  const result = await instrumentRawMime(raw, {
    openPixelUrl: 'https://mail.example/t/o/open.gif',
    createClickUrl: () => 'https://mail.example/t/c/click'
  });

  assert.equal(result.tracked, false);
  assert.equal(result.linkCount, 0);
  assert.equal(result.pixelAdded, false);
  assert.match(result.rawMessage, /https:\/\/example\.com\/signed/);
  assert.doesNotMatch(result.rawMessage, /mail\.example\/t\//);
});

test('rewrites non-UTF-8 HTML without corrupting its charset', async () => {
  const html = Buffer.from(
    '<html><body><p>Ol\xE1</p><a href="https://example.com/a">A</a></body></html>',
    'latin1'
  );
  const raw = [
    'From: sender@example.com',
    'To: user@example.net',
    'MIME-Version: 1.0',
    'Content-Type: text/html; charset=iso-8859-1',
    'Content-Transfer-Encoding: base64',
    '',
    html.toString('base64'),
    ''
  ].join('\r\n');

  const result = await instrumentRawMime(raw, {
    openPixelUrl: 'https://mail.example/t/o/open.gif',
    createClickUrl: () => 'https://mail.example/t/c/click'
  });

  assert.equal(result.tracked, true);
  assert.match(result.rawMessage, /Content-Type: text\/html; charset=utf-8/i);
  const encodedHtml = result.rawMessage.split(/\r?\n\r?\n/, 2)[1] || '';
  const decodedHtml = Buffer.from(encodedHtml.replace(/\s+/g, ''), 'base64').toString('utf8');
  assert.match(decodedHtml, /Ol\u00e1/);
  assert.match(decodedHtml, /mail\.example\/t\/c\/click/);
});

test('removes submission control headers without changing the MIME body', async () => {
  const raw = [
    'From: sender@example.com',
    'X-MailHub-Track: opens,clicks',
    'Subject: Hello',
    'Content-Type: text/plain; charset=UTF-8',
    '',
    'Body stays intact.',
    ''
  ].join('\r\n');
  const stripped = await stripRawMimeHeaders(raw, ['x-mailhub-track']);
  assert.doesNotMatch(stripped, /^X-MailHub-Track:/im);
  assert.match(stripped, /Body stays intact\.\r\n$/);

  const signed = `DKIM-Signature: v=1; d=example.com; b=x\r\nX-MailHub-Track: off\r\n\r\nBody\r\n`;
  assert.equal(await stripRawMimeHeaders(signed, ['x-mailhub-track']), signed);
});
