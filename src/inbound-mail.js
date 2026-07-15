import { Readable, Writable } from 'node:stream';
import { Splitter, Streamer } from '@zone-eu/mailsplit';
import { extractAddress, parseAddressList } from './mailer.js';

export async function parseInboundMessage(rawMessage, envelopeRecipients = []) {
  const source = String(rawMessage || '');
  const textParts = await collectTextParts(source);
  const textBody = textParts.find((part) => part.contentType === 'text/plain')?.body || '';
  const htmlBody = textParts.find((part) => part.contentType === 'text/html')?.body || '';
  const recipients = normalizeRecipients(envelopeRecipients);
  const headerRecipients = [
    ...parseAddressList(extractHeader(source, 'to')),
    ...parseAddressList(extractHeader(source, 'cc'))
  ];

  return {
    sender: extractAddress(extractHeader(source, 'from')) || extractAddress(extractHeader(source, 'sender')),
    recipients: recipients.length ? recipients : normalizeRecipients(headerRecipients),
    subject: decodeHeader(extractHeader(source, 'subject')) || '(no subject)',
    messageId: extractHeader(source, 'message-id'),
    rawMessage: source,
    textBody,
    htmlBody,
    preview: previewText(textBody || htmlToText(htmlBody) || source)
  };
}

async function collectTextParts(rawMessage) {
  const parts = [];
  const splitter = new Splitter({ ignoreEmbedded: true });
  const streamer = new Streamer((node) => (
    ['text/plain', 'text/html'].includes(node.contentType) && node.disposition !== 'attachment'
  ));
  const drain = new Writable({
    objectMode: true,
    write(_chunk, _encoding, callback) {
      callback();
    }
  });

  streamer.on('node', (data) => {
    const chunks = [];
    data.decoder.on('data', (chunk) => chunks.push(Buffer.from(chunk)));
    data.decoder.on('end', () => {
      parts.push({
        contentType: data.node.contentType,
        body: decodeText(Buffer.concat(chunks), data.node.charset)
      });
      data.done();
    });
    data.decoder.on('error', () => data.done());
  });

  await new Promise((resolve, reject) => {
    drain.on('finish', resolve);
    drain.on('error', reject);
    splitter.on('error', reject);
    streamer.on('error', reject);
    Readable.from([Buffer.from(rawMessage)]).pipe(splitter).pipe(streamer).pipe(drain);
  });

  if (!parts.length) {
    const body = rawMessage.split(/\r?\n\r?\n/).slice(1).join('\n\n').trim();
    if (body) parts.push({ contentType: 'text/plain', body });
  }

  return parts;
}

function extractHeader(rawMessage, name) {
  const head = rawMessage.split(/\r?\n\r?\n/, 1)[0] || '';
  const lines = head.split(/\r?\n/);
  const headers = [];
  for (const line of lines) {
    if (/^[\t ]/.test(line) && headers.length) {
      headers[headers.length - 1].value += ` ${line.trim()}`;
      continue;
    }
    const index = line.indexOf(':');
    if (index === -1) continue;
    headers.push({
      name: line.slice(0, index).toLowerCase(),
      value: line.slice(index + 1).trim()
    });
  }
  return headers.find((header) => header.name === name.toLowerCase())?.value || '';
}

function decodeHeader(value) {
  return String(value || '').replace(/=\?([^?]+)\?([bq])\?([^?]+)\?=/gi, (_, charset, encoding, encoded) => {
    const buffer = encoding.toLowerCase() === 'b'
      ? Buffer.from(encoded, 'base64')
      : Buffer.from(encoded.replace(/_/g, ' ').replace(/=([a-f0-9]{2})/gi, (_hex, value) => (
          String.fromCharCode(Number.parseInt(value, 16))
        )), 'binary');
    return decodeText(buffer, charset);
  });
}

function decodeText(buffer, charset) {
  const normalized = String(charset || 'utf-8').trim().toLowerCase();
  if (['iso-8859-1', 'latin1', 'latin-1'].includes(normalized)) return buffer.toString('latin1').trim();
  return buffer.toString('utf8').trim();
}

function normalizeRecipients(values) {
  return [...new Set((Array.isArray(values) ? values : [values]).map(extractAddress).filter(Boolean))];
}

function previewText(value) {
  return String(value || '').replace(/\s+/g, ' ').trim().slice(0, 240);
}

function htmlToText(value) {
  return String(value || '')
    .replace(/<style[\s\S]*?<\/style>/gi, ' ')
    .replace(/<script[\s\S]*?<\/script>/gi, ' ')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&nbsp;/gi, ' ')
    .replace(/&amp;/gi, '&')
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .replace(/&quot;/gi, '"')
    .replace(/&#39;/g, "'");
}
