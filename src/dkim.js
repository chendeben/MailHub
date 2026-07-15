import crypto from 'node:crypto';

export function createDkimKeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: {
      type: 'spki',
      format: 'pem'
    },
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'pem'
    }
  });
  return {
    publicKey: pemToDkimPublic(publicKey),
    privateKey
  };
}

export function pemToDkimPublic(pem) {
  return pem
    .replace(/-----BEGIN (?:RSA )?PUBLIC KEY-----/g, '')
    .replace(/-----END (?:RSA )?PUBLIC KEY-----/g, '')
    .replace(/\s+/g, '');
}

export function dkimPublicFromPrivateKey(privateKey) {
  const publicKey = crypto
    .createPublicKey(privateKey)
    .export({ type: 'spki', format: 'pem' });
  return pemToDkimPublic(publicKey);
}

export function buildDkimRecord(publicKey) {
  return `v=DKIM1; k=rsa; p=${publicKey}`;
}

export function signDkim(rawMessage, options) {
  const headers = parseHeaders(rawMessage);
  const body = rawMessage.slice(rawMessage.indexOf('\r\n\r\n') + 4);
  const baseSignedHeaderNames = [
    'from',
    'to',
    'subject',
    'date',
    'message-id',
    'mime-version',
    'content-type'
  ];
  const optionalSignedHeaderNames = [
    'list-unsubscribe',
    'list-unsubscribe-post',
    'feedback-id',
    'x-report-abuse-to',
    'x-csa-complaints',
    'x-sender',
    'sender',
    'reply-to'
  ];
  const presentHeaderNames = new Set(headers.map((header) => header.name.toLowerCase()));
  const signedHeaderNames = [
    ...baseSignedHeaderNames,
    ...optionalSignedHeaderNames.filter((name) => presentHeaderNames.has(name))
  ];
  const bodyHash = crypto
    .createHash('sha256')
    .update(canonicalizeBody(body))
    .digest('base64');

  const now = Math.floor(Date.now() / 1000);
  const signatureFields = [
    'v=1',
    'a=rsa-sha256',
    'c=relaxed/relaxed',
    'q=dns/txt',
    `d=${options.domain}`,
    `i=${options.identity || `@${options.domain}`}`,
    `s=${options.selector}`,
    `t=${now}`,
    `h=${signedHeaderNames.join(':')}`,
    `bh=${bodyHash}`,
    'b='
  ];
  if (Number.isInteger(options.expiresInSeconds) && options.expiresInSeconds > 0) {
    signatureFields.splice(signatureFields.length - 2, 0, `x=${now + options.expiresInSeconds}`);
  }
  const dkimValueWithoutSignature = signatureFields.join('; ');
  const signingInput = [
    ...signedHeaderNames.map((name) => canonicalizeHeader(findHeader(headers, name))),
    canonicalizeHeader({ name: 'DKIM-Signature', value: dkimValueWithoutSignature }, '')
  ].join('');

  const signature = crypto
    .createSign('RSA-SHA256')
    .update(signingInput)
    .sign(options.privateKey, 'base64');

  const folded = foldHeader('DKIM-Signature', `${dkimValueWithoutSignature}${signature}`);
  return `${folded}\r\n${rawMessage}`;
}

function parseHeaders(rawMessage) {
  const head = rawMessage.slice(0, rawMessage.indexOf('\r\n\r\n'));
  const lines = head.split('\r\n');
  const headers = [];
  for (const line of lines) {
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

function findHeader(headers, name) {
  const found = [...headers].reverse().find((header) => header.name.toLowerCase() === name);
  if (!found) return { name, value: '' };
  return found;
}

function canonicalizeHeader(header, suffix = '\r\n') {
  const name = header.name.toLowerCase();
  const value = header.value.replace(/\s+/g, ' ').trim();
  return `${name}:${value}${suffix}`;
}

function canonicalizeBody(body) {
  const lines = String(body || '')
    .replace(/\r?\n/g, '\r\n')
    .split('\r\n')
    .map((line) => line.replace(/[ \t]+$/g, '').replace(/[ \t]+/g, ' '));
  while (lines.length && lines[lines.length - 1] === '') lines.pop();
  return `${lines.join('\r\n')}\r\n`;
}

export function foldHeader(name, value) {
  const prefix = `${name}: `;
  const limit = 76;
  const words = value.split(' ');
  const lines = [];
  let current = prefix;
  for (const word of words) {
    if ((current + word).length > limit && current.trim() !== `${name}:`) {
      lines.push(current.trimEnd());
      current = ` ${word} `;
    } else {
      current += `${word} `;
    }
  }
  lines.push(current.trimEnd());
  return lines.join('\r\n');
}
