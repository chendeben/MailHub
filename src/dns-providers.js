import crypto from 'node:crypto';

const CLOUDFLARE_API = 'https://api.cloudflare.com/client/v4';
const ALIYUN_ENDPOINT = 'https://alidns.aliyuncs.com/';
const TENCENT_ENDPOINT = 'https://dnspod.tencentcloudapi.com';

export async function testDnsCredential(credential) {
  try {
    const provider = createProvider(credential);
    const result = await provider.test();
    return { ok: true, provider: credential.provider, detail: result };
  } catch (error) {
    return { ok: false, provider: credential.provider, error: error.message };
  }
}

export async function applyDnsSetup(domain, credential, guide) {
  const provider = createProvider(credential);
  const records = (guide.records || []).filter((record) => ['verification', 'dkim', 'spf', 'dmarc'].includes(record.key));
  const results = [];
  for (const record of records) {
    const zoneName = effectiveZoneName(credential, domain, record);
    if (zoneName && !isHostInZone(record.host, zoneName)) {
      results.push(outOfZoneResult(record, zoneName));
      continue;
    }
    try {
      const result = await provider.upsert(record, domain);
      results.push({ key: record.key, host: record.host, type: record.type, ok: true, detail: result });
    } catch (error) {
      results.push({ key: record.key, host: record.host, type: record.type, ok: false, error: error.message });
    }
  }
  return {
    ok: results.every((result) => result.ok),
    provider: credential.provider,
    appliedAt: new Date().toISOString(),
    results
  };
}

function createProvider(credential) {
  if (credential.provider === 'cloudflare') return new CloudflareProvider(credential);
  if (credential.provider === 'aliyun') return new AliyunProvider(credential);
  if (credential.provider === 'dnspod') return new DnspodProvider(credential);
  throw new Error('DNS 服务商不支持。');
}

class CloudflareProvider {
  constructor(credential) {
    this.credential = credential;
    this.credentials = credential.credentials || {};
    this.zoneName = credential.zoneName;
    this.ttl = credential.defaultTtl || 600;
    this.zoneIdCache = new Map();
  }

  async test() {
    const zoneId = await this.zoneId();
    const zone = await this.request(`/zones/${zoneId}`);
    return zone.result?.name || this.zoneName || zoneId;
  }

  async upsert(record, domain) {
    const zoneId = await this.zoneId(record, domain);
    const existing = await this.listRecords(zoneId, record);
    const match = pickExisting(record, existing);
    const payload = {
      type: record.type,
      name: record.host,
      content: record.value,
      ttl: this.ttl,
      proxied: false
    };
    if (match) {
      await this.request(`/zones/${zoneId}/dns_records/${match.id}`, {
        method: 'PUT',
        body: payload
      });
      await this.deleteExtras(zoneId, existing, match, record);
      return 'updated';
    }
    try {
      await this.request(`/zones/${zoneId}/dns_records`, { method: 'POST', body: payload });
    } catch (error) {
      if (/identical record already exists/i.test(error.message)) return 'unchanged';
      throw error;
    }
    await this.deleteExtras(zoneId, existing, null, record);
    return 'created';
  }

  async deleteExtras(zoneId, records, kept, desired) {
    if (!['spf', 'dmarc'].includes(desired.key)) return;
    const extras = records.filter((record) => record.id !== kept?.id && recordMatchesKind(desired, record.content));
    for (const record of extras) await this.request(`/zones/${zoneId}/dns_records/${record.id}`, { method: 'DELETE' });
  }

  async listRecords(zoneId, record) {
    const records = [];
    let page = 1;
    let totalPages = 1;
    do {
      const params = new URLSearchParams({
        type: record.type,
        'name.exact': record.host,
        match: 'all',
        page: String(page),
        per_page: '100'
      });
      const response = await this.request(`/zones/${zoneId}/dns_records?${params}`);
      records.push(
        ...(response.result || []).filter((item) => item.type === record.type && sameDnsName(item.name, record.host))
      );
      totalPages = Number(response.result_info?.total_pages || page);
      page += 1;
    } while (page <= totalPages);
    return records;
  }

  async zoneId(record, domain) {
    const targetZoneName = await this.resolveZoneName(record, domain);
    if (this.credentials.zoneId && (!targetZoneName || sameZone(targetZoneName, this.zoneName))) {
      return this.credentials.zoneId;
    }
    if (!targetZoneName) throw new Error('Cloudflare 需要 zoneName、zoneId 或发信域名。');
    return this.lookupZoneId(targetZoneName);
  }

  async resolveZoneName(record, domain) {
    const host = record?.host || '';
    const domainName = domain?.domain || '';
    const candidates = uniqueZoneCandidates([
      this.zoneName,
      ...zoneCandidates(domainName || host)
    ]).filter((candidate) => !host || isHostInZone(host, candidate));
    for (const candidate of candidates) {
      const zoneId = await this.lookupZoneId(candidate, { optional: true });
      if (zoneId) return candidate;
    }
    return this.zoneName || domainName;
  }

  async lookupZoneId(zoneName, { optional = false } = {}) {
    const cleanZone = normalizeZoneName(zoneName);
    if (!cleanZone) return '';
    if (this.zoneIdCache.has(cleanZone)) return this.zoneIdCache.get(cleanZone);
    const response = await this.request(`/zones?name=${encodeURIComponent(cleanZone)}`);
    const zone = response.result?.[0];
    if (!zone?.id) {
      if (optional) {
        this.zoneIdCache.set(cleanZone, '');
        return '';
      }
      throw new Error(`Cloudflare 未找到 Zone ${cleanZone}。`);
    }
    this.zoneIdCache.set(cleanZone, zone.id);
    return zone.id;
  }

  async request(path, options = {}) {
    if (!this.credentials.apiToken) throw new Error('Cloudflare API Token 不能为空。');
    const response = await fetch(`${CLOUDFLARE_API}${path}`, {
      method: options.method || 'GET',
      headers: {
        Authorization: `Bearer ${this.credentials.apiToken}`,
        'Content-Type': 'application/json'
      },
      body: options.body ? JSON.stringify(options.body) : undefined
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok || data.success === false) {
      const message = data.errors?.map((error) => error.message).join('; ') || `Cloudflare HTTP ${response.status}`;
      throw new Error(message);
    }
    return data;
  }
}

class AliyunProvider {
  constructor(credential) {
    this.credential = credential;
    this.credentials = credential.credentials || {};
    this.zoneName = credential.zoneName;
    this.ttl = credential.defaultTtl || 600;
  }

  async test() {
    const response = await this.request('DescribeDomainRecords', { DomainName: this.zoneName, PageSize: 1 });
    return response.DomainRecords?.Record?.length >= 0 ? this.zoneName : 'ok';
  }

  async upsert(record, domain) {
    const zoneName = await this.resolveZoneName(record, domain);
    const rr = relativeName(record.host, zoneName);
    const existing = await this.listRecords(zoneName, record.type, rr);
    const match = pickExisting(record, existing);
    const params = {
      RR: rr,
      Type: record.type,
      Value: record.value,
      TTL: this.ttl
    };
    if (match) {
      await this.request('UpdateDomainRecord', { ...params, RecordId: match.id });
      await this.deleteExtras(zoneName, existing, match, record);
      return 'updated';
    }
    await this.request('AddDomainRecord', { DomainName: zoneName, ...params });
    await this.deleteExtras(zoneName, existing, null, record);
    return 'created';
  }

  async deleteExtras(zoneName, records, kept, desired) {
    if (!['spf', 'dmarc'].includes(desired.key)) return;
    const extras = records.filter((record) => record.id !== kept?.id && recordMatchesKind(desired, record.value));
    for (const record of extras) await this.request('DeleteDomainRecord', { RecordId: record.id });
  }

  async listRecords(zoneName, type, rr) {
    const response = await this.request('DescribeDomainRecords', {
      DomainName: zoneName,
      RRKeyWord: rr === '@' ? '' : rr,
      TypeKeyWord: type,
      PageSize: 100
    });
    return (response.DomainRecords?.Record || [])
      .filter((record) => record.RR === rr && record.Type === type)
      .map((record) => ({
        id: String(record.RecordId),
        type: record.Type,
        name: record.RR,
        value: record.Value
      }));
  }

  async resolveZoneName(record, domain) {
    const host = record?.host || '';
    const candidates = uniqueZoneCandidates([
      this.zoneName,
      ...zoneCandidates(domain?.domain || host)
    ]).filter((candidate) => isHostInZone(host, candidate));
    for (const candidate of candidates) {
      const rr = relativeName(host, candidate);
      try {
        await this.listRecords(candidate, record.type, rr);
        return candidate;
      } catch (error) {
        if (!isAliyunZoneMissingError(error)) throw error;
      }
    }
    return this.zoneName;
  }

  async request(action, params) {
    if (!this.zoneName) throw new Error('阿里云 DNS 需要 zoneName。');
    if (!this.credentials.accessKeyId || !this.credentials.accessKeySecret) {
      throw new Error('阿里云 AccessKeyId 和 AccessKeySecret 不能为空。');
    }
    const common = {
      Action: action,
      Version: '2015-01-09',
      Format: 'JSON',
      AccessKeyId: this.credentials.accessKeyId,
      SignatureMethod: 'HMAC-SHA1',
      Timestamp: new Date().toISOString(),
      SignatureVersion: '1.0',
      SignatureNonce: crypto.randomUUID()
    };
    const signed = signAliyun({ ...common, ...params }, this.credentials.accessKeySecret);
    const response = await fetch(`${ALIYUN_ENDPOINT}?${signed}`);
    const data = await response.json().catch(() => ({}));
    if (!response.ok || data.Code) {
      const error = new Error(data.Message || data.Code || `Aliyun HTTP ${response.status}`);
      error.code = data.Code || '';
      throw error;
    }
    return data;
  }
}

class DnspodProvider {
  constructor(credential) {
    this.credential = credential;
    this.credentials = credential.credentials || {};
    this.zoneName = credential.zoneName;
    this.ttl = credential.defaultTtl || 600;
  }

  async test() {
    await this.request('DescribeRecordList', { Domain: this.zoneName, Limit: 1 });
    return this.zoneName;
  }

  async upsert(record, domain) {
    const zoneName = await this.resolveZoneName(record, domain);
    const subDomain = relativeName(record.host, zoneName);
    const existing = await this.listRecords(zoneName, record.type, subDomain);
    const match = pickExisting(record, existing);
    const params = {
      Domain: zoneName,
      SubDomain: subDomain,
      RecordType: record.type,
      RecordLine: '默认',
      Value: record.value,
      TTL: this.ttl
    };
    if (match) {
      await this.request('ModifyRecord', { ...params, RecordId: Number(match.id) });
      await this.deleteExtras(zoneName, existing, match, record);
      return 'updated';
    }
    await this.request('CreateRecord', params);
    await this.deleteExtras(zoneName, existing, null, record);
    return 'created';
  }

  async deleteExtras(zoneName, records, kept, desired) {
    if (!['spf', 'dmarc'].includes(desired.key)) return;
    const extras = records.filter((record) => record.id !== kept?.id && recordMatchesKind(desired, record.value));
    for (const record of extras) {
      await this.request('DeleteRecord', { Domain: zoneName, RecordId: Number(record.id) });
    }
  }

  async listRecords(zoneName, type, subDomain) {
    const response = await this.request('DescribeRecordList', {
      Domain: zoneName,
      Subdomain: subDomain,
      RecordType: type,
      Limit: 100
    });
    return (response.RecordList || [])
      .filter((record) => record.Name === subDomain && record.Type === type)
      .map((record) => ({
        id: String(record.RecordId),
        type: record.Type,
        name: record.Name,
        value: record.Value
      }));
  }

  async resolveZoneName(record, domain) {
    const host = record?.host || '';
    const candidates = uniqueZoneCandidates([
      this.zoneName,
      ...zoneCandidates(domain?.domain || host)
    ]).filter((candidate) => isHostInZone(host, candidate));
    for (const candidate of candidates) {
      const subDomain = relativeName(host, candidate);
      try {
        await this.listRecords(candidate, record.type, subDomain);
        return candidate;
      } catch (error) {
        if (!isDnsPodZoneMissingError(error)) throw error;
      }
    }
    return this.zoneName;
  }

  async request(action, payload) {
    if (!this.zoneName) throw new Error('腾讯云 DNSPod 需要 zoneName。');
    if (!this.credentials.secretId || !this.credentials.secretKey) throw new Error('腾讯云 SecretId 和 SecretKey 不能为空。');
    const timestamp = Math.floor(Date.now() / 1000);
    const body = JSON.stringify(payload);
    const headers = signTencent({
      action,
      body,
      secretId: this.credentials.secretId,
      secretKey: this.credentials.secretKey,
      timestamp
    });
    const response = await fetch(TENCENT_ENDPOINT, {
      method: 'POST',
      headers,
      body
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok || data.Response?.Error) {
      const error = new Error(data.Response?.Error?.Message || `Tencent Cloud HTTP ${response.status}`);
      error.code = data.Response?.Error?.Code || '';
      if (action === 'DescribeRecordList' && isDnsPodEmptyRecordListError(error)) {
        return { RecordList: [] };
      }
      throw error;
    }
    return data.Response;
  }
}

function pickExisting(desired, existing) {
  if (desired.key === 'spf' || desired.key === 'dmarc') {
    return existing.find((record) => recordMatchesKind(desired, record.content || record.value));
  }
  return existing.find((record) => normalizeValue(record.content || record.value) === normalizeValue(desired.value)) || existing[0] || null;
}

function recordMatchesKind(desired, value) {
  const normalized = normalizeValue(value);
  if (desired.key === 'spf') return /^v=spf1(?:\s|$)/i.test(normalized);
  if (desired.key === 'dmarc') return /^v=DMARC1(?:;|\s|$)/i.test(normalized);
  return normalizeValue(value) === normalizeValue(desired.value);
}

function normalizeValue(value) {
  return unquoteTxtValue(String(value || '').replace(/\s+/g, ' ').trim());
}

function unquoteTxtValue(value) {
  if (value.length < 2 || !value.startsWith('"') || !value.endsWith('"')) return value;
  return value.slice(1, -1).replace(/\\"/g, '"');
}

function sameDnsName(left, right) {
  return normalizeZoneName(left) === normalizeZoneName(right);
}

function relativeName(host, zoneName) {
  const cleanHost = String(host || '').replace(/\.$/, '').toLowerCase();
  const cleanZone = String(zoneName || '').replace(/\.$/, '').toLowerCase();
  if (!cleanZone) throw new Error('DNS 凭据缺少 zoneName。');
  if (cleanHost === cleanZone) return '@';
  if (cleanHost.endsWith(`.${cleanZone}`)) return cleanHost.slice(0, -cleanZone.length - 1) || '@';
  throw new Error(`记录 ${host} 不在 DNS Zone ${zoneName} 下。`);
}

function isHostInZone(host, zoneName) {
  const cleanHost = String(host || '').replace(/\.$/, '').toLowerCase();
  const cleanZone = String(zoneName || '').replace(/\.$/, '').toLowerCase();
  return Boolean(cleanHost && cleanZone && (cleanHost === cleanZone || cleanHost.endsWith(`.${cleanZone}`)));
}

function effectiveZoneName(credential, domain, record) {
  if (credential.provider !== 'cloudflare') return credential.zoneName || '';
  const configuredZone = credential.zoneName || '';
  if (configuredZone && isHostInZone(record.host, configuredZone)) return configuredZone;
  return domain?.domain || configuredZone;
}

function sameZone(left, right) {
  return normalizeZoneName(left) === normalizeZoneName(right);
}

function normalizeZoneName(value) {
  return String(value || '').replace(/\.$/, '').toLowerCase();
}

function zoneCandidates(name) {
  const clean = normalizeZoneName(name);
  const parts = clean.split('.').filter(Boolean);
  const candidates = [];
  for (let index = 0; index <= parts.length - 2; index += 1) {
    candidates.push(parts.slice(index).join('.'));
  }
  return candidates;
}

function uniqueZoneCandidates(candidates) {
  const seen = new Set();
  const output = [];
  for (const candidate of candidates) {
    const clean = normalizeZoneName(candidate);
    if (!clean || seen.has(clean)) continue;
    seen.add(clean);
    output.push(clean);
  }
  return output;
}

function isDnsPodZoneMissingError(error) {
  const code = String(error?.code || '');
  const message = String(error?.message || '');
  return /NoDataOfRecord|ResourceNotFound|DomainNotExists|InvalidParameter\.Domain/i.test(code)
    || /domain not found|domain does not exist|域名.*(不存在|没有)|没有.*域名/i.test(message);
}

function isDnsPodEmptyRecordListError(error) {
  const code = String(error?.code || '');
  const message = String(error?.message || '');
  return /RecordListEmpty/i.test(code)
    || /记录列表为空|record list.*empty|empty record list/i.test(message);
}

function isAliyunZoneMissingError(error) {
  const code = String(error?.code || '');
  const message = String(error?.message || '');
  return /InvalidDomainName|DomainRecordNotBelongToUser|DomainNotExists|DomainNameNotFound/i.test(code)
    || /domain not found|domain does not exist|域名.*(不存在|没有)|没有.*域名/i.test(message);
}

function outOfZoneResult(record, zoneName) {
  const base = {
    key: record.key,
    host: record.host,
    type: record.type
  };
  if (record.key === 'sender-a' && record.status === 'ok') {
    return {
      ...base,
      ok: true,
      skipped: true,
      detail: `发信主机不在 ${zoneName} Zone 下，已跳过；当前 A 记录已正确解析。`
    };
  }
  return {
    ...base,
    ok: false,
    skipped: true,
    error: `记录 ${record.host} 不在 DNS Zone ${zoneName} 下，请绑定正确的 DNS API 或手动配置。`
  };
}

function signAliyun(params, accessKeySecret) {
  const encoded = Object.keys(params)
    .sort()
    .map((key) => `${percentEncode(key)}=${percentEncode(params[key])}`)
    .join('&');
  const stringToSign = `GET&%2F&${percentEncode(encoded)}`;
  const signature = crypto
    .createHmac('sha1', `${accessKeySecret}&`)
    .update(stringToSign)
    .digest('base64');
  return `${encoded}&Signature=${percentEncode(signature)}`;
}

function percentEncode(value) {
  return encodeURIComponent(String(value))
    .replace(/\+/g, '%20')
    .replace(/\*/g, '%2A')
    .replace(/%7E/g, '~');
}

function signTencent({ action, body, secretId, secretKey, timestamp }) {
  const service = 'dnspod';
  const host = 'dnspod.tencentcloudapi.com';
  const date = new Date(timestamp * 1000).toISOString().slice(0, 10);
  const hashedPayload = sha256(body, 'hex');
  const canonicalRequest = [
    'POST',
    '/',
    '',
    `content-type:application/json; charset=utf-8\nhost:${host}\n`,
    'content-type;host',
    hashedPayload
  ].join('\n');
  const credentialScope = `${date}/${service}/tc3_request`;
  const stringToSign = [
    'TC3-HMAC-SHA256',
    String(timestamp),
    credentialScope,
    sha256(canonicalRequest, 'hex')
  ].join('\n');
  const secretDate = hmac(`TC3${secretKey}`, date);
  const secretService = hmac(secretDate, service);
  const secretSigning = hmac(secretService, 'tc3_request');
  const signature = hmac(secretSigning, stringToSign, 'hex');
  return {
    Authorization: `TC3-HMAC-SHA256 Credential=${secretId}/${credentialScope}, SignedHeaders=content-type;host, Signature=${signature}`,
    'Content-Type': 'application/json; charset=utf-8',
    Host: host,
    'X-TC-Action': action,
    'X-TC-Version': '2021-03-23',
    'X-TC-Timestamp': String(timestamp),
    'X-TC-Region': 'ap-guangzhou'
  };
}

function sha256(value, encoding) {
  return crypto.createHash('sha256').update(value).digest(encoding);
}

function hmac(key, value, encoding) {
  return crypto.createHmac('sha256', key).update(value).digest(encoding);
}
