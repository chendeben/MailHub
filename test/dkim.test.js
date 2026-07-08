import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { test } from 'node:test';
import { buildMessage, signMessageForDomain } from '../src/mailer.js';
import { createDkimKeyPair } from '../src/dkim.js';

test('signs messages with a verifiable DKIM relaxed body hash', () => {
  const keys = createDkimKeyPair();
  const raw = buildMessage({
    from: 'noreply@example.com',
    to: 'user@example.net',
    subject: '中文 DKIM test',
    text: 'Hello   MailHub  \n中文正文\twith spacing',
    baseUrl: 'https://mailhub.test'
  });
  const signed = signMessageForDomain(raw, {
    domain: 'example.com',
    selector: 'mh202607',
    dkimPrivate: keys.privateKey
  });

  const verification = verifyDkimSignature(signed, keys.publicKey);
  assert.equal(verification.bodyHashValid, true);
  assert.equal(verification.signatureValid, true);
});

function verifyDkimSignature(rawMessage, publicKey) {
  const separator = rawMessage.indexOf('\r\n\r\n');
  const headers = parseHeaders(rawMessage.slice(0, separator));
  const body = rawMessage.slice(separator + 4);
  const dkim = headers.find((header) => header.name.toLowerCase() === 'dkim-signature');
  assert.ok(dkim);
  const tags = parseDkimTags(dkim.value);
  const bodyHash = crypto
    .createHash('sha256')
    .update(relaxedBody(body))
    .digest('base64');
  const dkimWithoutSignature = dkim.value.replace(/(^|;\s*)b=[^;]*/i, '$1b=');
  const signedHeaderNames = tags.h.split(':').map((name) => name.trim().toLowerCase()).filter(Boolean);
  const signingInput = [
    ...signedHeaderNames.map((name) => relaxedHeader(findLastHeader(headers, name))),
    relaxedHeader({ name: 'DKIM-Signature', value: dkimWithoutSignature }, '')
  ].join('');
  const signatureValid = crypto
    .createVerify('RSA-SHA256')
    .update(signingInput)
    .verify(dkimPublicPem(publicKey), tags.b, 'base64');
  return {
    bodyHashValid: bodyHash === tags.bh,
    signatureValid
  };
}

function parseHeaders(headerBlock) {
  const headers = [];
  for (const line of headerBlock.split('\r\n')) {
    if (/^[\t ]/.test(line) && headers.length) {
      headers[headers.length - 1].value += ` ${line.trim()}`;
      continue;
    }
    const index = line.indexOf(':');
    if (index === -1) continue;
    headers.push({
      name: line.slice(0, index),
      value: line.slice(index + 1)
    });
  }
  return headers;
}

function parseDkimTags(value) {
  const tags = {};
  for (const part of value.split(';')) {
    const index = part.indexOf('=');
    if (index === -1) continue;
    tags[part.slice(0, index).trim()] = part.slice(index + 1).trim();
  }
  return tags;
}

function findLastHeader(headers, name) {
  const found = [...headers].reverse().find((header) => header.name.toLowerCase() === name);
  return found || { name, value: '' };
}

function relaxedHeader(header, suffix = '\r\n') {
  return `${header.name.toLowerCase()}:${header.value.replace(/\s+/g, ' ').trim()}${suffix}`;
}

function relaxedBody(body) {
  const lines = String(body || '')
    .replace(/\r?\n/g, '\r\n')
    .split('\r\n')
    .map((line) => line.replace(/[ \t]+$/g, '').replace(/[ \t]+/g, ' '));
  while (lines.length && lines[lines.length - 1] === '') lines.pop();
  return `${lines.join('\r\n')}\r\n`;
}

function dkimPublicPem(publicKey) {
  return [
    '-----BEGIN PUBLIC KEY-----',
    publicKey.match(/.{1,64}/g).join('\n'),
    '-----END PUBLIC KEY-----',
    ''
  ].join('\n');
}
