import dns from 'node:dns';
import { buildDkimRecord } from './dkim.js';

const resolver = new dns.promises.Resolver();
resolver.setServers(
  String(process.env.DNS_RESOLVERS || '1.1.1.1,8.8.8.8')
    .split(',')
    .map((server) => server.trim())
    .filter(Boolean)
);

export async function buildDnsGuide(domain) {
  const live = await readLiveDns(domain);
  const requiredSpf = buildRequiredSpfMechanisms(domain);
  const spf = mergeSpfRecords(live.rootTxt.filter(isSpfRecord), requiredSpf);
  const dmarc = mergeDmarcRecord(live.dmarcTxt.find(isDmarcRecord), domain);
  const verificationValue = `mailhub-verification=${domain.verificationToken}`;
  const dkimValue = buildDkimRecord(domain.dkimPublic);
  const records = [
    {
      key: 'verification',
      label: '域名验证',
      host: `_mailhub.${domain.domain}`,
      type: 'TXT',
      value: verificationValue,
      status: containsTxt(live.verificationTxt, verificationValue) ? 'ok' : 'missing'
    },
    {
      key: 'dkim',
      label: 'DKIM',
      host: `${domain.selector}._domainkey.${domain.domain}`,
      type: 'TXT',
      value: dkimValue,
      status: containsTxt(live.dkimTxt, dkimValue) ? 'ok' : 'missing'
    },
    {
      key: 'spf',
      label: 'SPF',
      host: domain.domain,
      type: 'TXT',
      value: spf.recommended,
      status: spf.ok ? 'ok' : 'warn',
      current: spf.current,
      warnings: spf.warnings
    },
    {
      key: 'dmarc',
      label: 'DMARC',
      host: `_dmarc.${domain.domain}`,
      type: 'TXT',
      value: dmarc.recommended,
      status: dmarc.ok ? 'ok' : 'warn',
      current: dmarc.current,
      warnings: dmarc.warnings
    },
    {
      key: 'sender-a',
      label: '平台发信主机 A',
      host: domain.senderHost,
      type: 'A',
      value: domain.sendingIp,
      managed: true,
      status: live.senderA.includes(domain.sendingIp) ? 'ok' : 'warn',
      current: live.senderA.join(', '),
      warnings: live.senderA.includes(domain.sendingIp)
        ? []
        : [`${domain.senderHost} 当前未解析到 ${domain.sendingIp}，这是平台发信主机，请联系管理员检查。`]
    },
    {
      key: 'ptr',
      label: 'PTR 反向解析',
      host: domain.sendingIp,
      type: 'PTR',
      value: domain.senderHost,
      status: live.ptr.includes(domain.senderHost) ? 'ok' : 'warn',
      current: live.ptr.join(', '),
      warnings: live.ptr.includes(domain.senderHost)
        ? []
        : ['PTR 需要在云服务器或 IP 服务商控制台设置，普通 DNS 控制台通常不能修改。']
    }
  ];

  const okKeys = new Set(records.filter((record) => record.status === 'ok').map((record) => record.key));
  const verified = okKeys.has('verification') && okKeys.has('dkim') && okKeys.has('spf') && okKeys.has('dmarc');

  return {
    checkedAt: new Date().toISOString(),
    verified,
    records,
    live,
    requiredSpf,
    optionalRecords: buildOptionalRecords(domain),
    warnings: collectWarnings(records, spf, dmarc, live)
  };
}

async function readLiveDns(domain) {
  const [
    rootTxt,
    verificationTxt,
    dkimTxt,
    dmarcTxt,
    senderA,
    ptr
  ] = await Promise.all([
    resolveTxt(domain.domain),
    resolveTxt(`_mailhub.${domain.domain}`),
    resolveTxt(`${domain.selector}._domainkey.${domain.domain}`),
    resolveTxt(`_dmarc.${domain.domain}`),
    resolve4(domain.senderHost),
    resolvePtr(domain.sendingIp)
  ]);
  return {
    rootTxt,
    verificationTxt,
    dkimTxt,
    dmarcTxt,
    senderA,
    ptr
  };
}

async function resolveTxt(name) {
  try {
    const rows = await resolver.resolveTxt(name);
    return rows.map((parts) => parts.join(''));
  } catch (error) {
    if (['ENODATA', 'ENOTFOUND', 'SERVFAIL', 'ETIMEOUT'].includes(error.code)) return [];
    return [`DNS lookup failed: ${error.code || error.message}`];
  }
}

async function resolve4(name) {
  try {
    return await resolver.resolve4(name);
  } catch {
    return [];
  }
}

async function resolvePtr(ip) {
  try {
    return await resolver.reverse(ip);
  } catch {
    return [];
  }
}

function containsTxt(records, expected) {
  return records.some((record) => normalizeTxt(record) === normalizeTxt(expected));
}

function normalizeTxt(value) {
  return String(value).replace(/\s+/g, ' ').trim();
}

function isSpfRecord(value) {
  return /^v=spf1(?:\s|$)/i.test(value.trim());
}

function isDmarcRecord(value) {
  return /^v=DMARC1(?:;|\s|$)/i.test(value.trim());
}

function buildRequiredSpfMechanisms(domain) {
  const mechanisms = [];
  if (domain.sendingIp) mechanisms.push(`ip4:${domain.sendingIp}`);
  if (domain.senderHost) mechanisms.push(`a:${domain.senderHost}`);
  mechanisms.push(...splitMechanisms(domain.spfExtra));
  return uniqueMechanisms(mechanisms);
}

function splitMechanisms(value) {
  return String(value || '')
    .split(/[\s,]+/)
    .map((item) => item.trim())
    .filter(Boolean);
}

export function mergeSpfRecords(existingRecords, requiredMechanisms) {
  const warnings = [];
  const current = existingRecords.map(normalizeTxt);
  if (current.length > 1) {
    warnings.push('当前域名存在多条 SPF TXT，收件方会判定 SPF permerror；需要合并为一条。');
  }
  if (current.length === 0) {
    const recommended = `v=spf1 ${requiredMechanisms.join(' ')} ~all`.replace(/\s+/g, ' ').trim();
    warnings.push('当前没有 SPF 记录。');
    return {
      current,
      recommended,
      ok: false,
      warnings: withLookupWarning(warnings, recommended)
    };
  }

  const parsed = current.map(parseSpf);
  const mechanisms = [];
  for (const record of parsed) mechanisms.push(...record.mechanisms);
  mechanisms.push(...requiredMechanisms);

  const all = parsed.find((record) => record.all === '-all')?.all
    || parsed.find((record) => record.all === '~all')?.all
    || parsed.find((record) => record.all === '?all')?.all
    || '~all';
  const recommended = `v=spf1 ${uniqueMechanisms(mechanisms).join(' ')} ${all}`
    .replace(/\s+/g, ' ')
    .trim();
  const ok = current.length === 1
    && normalizeTxt(current[0]) === recommended
    && requiredMechanisms.every((mechanism) => hasMechanism(current[0], mechanism));

  return {
    current,
    recommended,
    ok,
    warnings: withLookupWarning(warnings, recommended)
  };
}

function parseSpf(record) {
  const tokens = normalizeTxt(record).split(/\s+/).slice(1);
  const mechanisms = [];
  let all = '~all';
  for (const token of tokens) {
    if (/^[+\-~?]?all$/i.test(token)) {
      all = token;
    } else if (token) {
      mechanisms.push(token);
    }
  }
  return { mechanisms, all };
}

function uniqueMechanisms(items) {
  const seen = new Set();
  const output = [];
  for (const item of items) {
    const normalized = normalizeMechanism(item);
    if (!normalized || seen.has(normalized)) continue;
    seen.add(normalized);
    output.push(item.replace(/^\+/, ''));
  }
  return output;
}

function normalizeMechanism(item) {
  return String(item || '').trim().replace(/^\+/, '').toLowerCase();
}

function hasMechanism(record, mechanism) {
  const normalized = normalizeMechanism(mechanism);
  return parseSpf(record).mechanisms.some((item) => normalizeMechanism(item) === normalized);
}

function withLookupWarning(warnings, spf) {
  const lookupCount = (spf.match(/\b(include|a|mx|ptr|exists|redirect)[=:]?/g) || []).length;
  if (lookupCount > 10) {
    return [...warnings, `SPF DNS 查询项约为 ${lookupCount} 个，超过 10 个会失败；建议减少 include 或改用专用子域。`];
  }
  if (lookupCount >= 8) {
    return [...warnings, `SPF DNS 查询项约为 ${lookupCount} 个，接近 10 个上限。`];
  }
  return warnings;
}

export function mergeDmarcRecord(existingRecord, domain) {
  const current = existingRecord ? normalizeTxt(existingRecord) : '';
  const warnings = [];
  const tags = parseDmarc(current);
  if (!current) warnings.push('当前没有 DMARC 记录。');
  tags.set('v', 'DMARC1');
  tags.set('p', domain.dmarcPolicy || tags.get('p') || 'none');
  tags.set('adkim', tags.get('adkim') || 's');
  tags.set('aspf', tags.get('aspf') || 's');
  tags.set('pct', tags.get('pct') || '100');
  const rua = domain.dmarcRua || tags.get('rua') || `mailto:dmarc@${domain.domain}`;
  if (rua) tags.set('rua', rua);
  const order = ['v', 'p', 'rua', 'ruf', 'adkim', 'aspf', 'pct', 'fo'];
  const recommended = [
    ...order.filter((key) => tags.has(key)).map((key) => `${key}=${tags.get(key)}`),
    ...[...tags.entries()]
      .filter(([key]) => !order.includes(key))
      .map(([key, value]) => `${key}=${value}`)
  ].join('; ');
  return {
    current: current ? [current] : [],
    recommended,
    ok: current === recommended,
    warnings
  };
}

function parseDmarc(record) {
  const tags = new Map();
  for (const part of String(record || '').split(';')) {
    const [key, ...rest] = part.trim().split('=');
    if (!key || !rest.length) continue;
    tags.set(key.toLowerCase(), rest.join('=').trim());
  }
  return tags;
}

function buildOptionalRecords(domain) {
  return [
    {
      label: 'TLS-RPT',
      host: `_smtp._tls.${domain.domain}`,
      type: 'TXT',
      value: `v=TLSRPTv1; rua=mailto:tlsrpt@${domain.domain}`
    },
    {
      label: 'MTA-STS',
      host: `_mta-sts.${domain.domain}`,
      type: 'TXT',
      value: 'v=STSv1; id=2026070701'
    },
    {
      label: 'BIMI',
      host: `default._bimi.${domain.domain}`,
      type: 'TXT',
      value: `v=BIMI1; l=https://${domain.domain}/bimi.svg`
    }
  ];
}

function collectWarnings(records, spf, dmarc, live) {
  const warnings = [
    ...records.flatMap((record) => record.warnings || []),
    ...spf.warnings,
    ...dmarc.warnings
  ];
  if (live.rootTxt.filter(isSpfRecord).length > 1) {
    warnings.push('SPF 必须只有一条 TXT；不要新增第二条 v=spf1。');
  }
  return [...new Set(warnings)];
}
