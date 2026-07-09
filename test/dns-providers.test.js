import assert from 'node:assert/strict';
import { afterEach, test } from 'node:test';
import { applyDnsSetup, testDnsCredential } from '../src/dns-providers.js';

const originalFetch = globalThis.fetch;

afterEach(() => {
  globalThis.fetch = originalFetch;
});

test('cloudflare provider tests credentials and replaces duplicate SPF records', async () => {
  const calls = [];
  globalThis.fetch = async (url, options = {}) => {
    calls.push({ url: String(url), method: options.method || 'GET', body: options.body });
    if (String(url).includes('/zones?')) return json({ success: true, result: [{ id: 'zone-1', name: 'example.com' }] });
    if (String(url).includes('/zones/zone-1') && !String(url).includes('/dns_records')) {
      return json({ success: true, result: { id: 'zone-1', name: 'example.com' } });
    }
    if (String(url).includes('/dns_records?')) {
      return json({
        success: true,
        result: [
          { id: 'spf-1', type: 'TXT', name: 'example.com', content: 'v=spf1 include:old ~all' },
          { id: 'spf-2', type: 'TXT', name: 'example.com', content: 'v=spf1 include:duplicate ~all' }
        ]
      });
    }
    return json({ success: true, result: { id: 'ok' } });
  };

  const credential = cloudflareCredential();
  assert.equal((await testDnsCredential(credential)).ok, true);
  const result = await applyDnsSetup(domainFixture(), credential, {
    records: [{ key: 'spf', host: 'example.com', type: 'TXT', value: 'v=spf1 ip4:127.0.0.1 ~all' }]
  });

  assert.equal(result.ok, true);
  assert.ok(calls.some((call) => call.method === 'PUT' && call.url.includes('/dns_records/spf-1')));
  assert.ok(calls.some((call) => call.method === 'DELETE' && call.url.includes('/dns_records/spf-2')));
});

test('cloudflare provider paginates exact record lookups before creating SPF records', async () => {
  const calls = [];
  globalThis.fetch = async (url, options = {}) => {
    const urlText = String(url);
    calls.push({ url: urlText, method: options.method || 'GET', body: options.body });
    if (urlText.includes('/zones?name=example.com')) {
      return json({ success: true, result: [{ id: 'zone-1', name: 'example.com' }] });
    }
    if (urlText.includes('/dns_records?')) {
      const params = new URL(urlText).searchParams;
      const page = Number(params.get('page') || 1);
      if (page === 1) {
        return json({
          success: true,
          result: [{ id: 'txt-1', type: 'TXT', name: 'example.com', content: 'google-site-verification=abc' }],
          result_info: { page: 1, total_pages: 2 }
        });
      }
      return json({
        success: true,
        result: [
          { id: 'spf-1', type: 'TXT', name: 'example.com', content: 'v=spf1 include:spf.mailjet.com +include:spf.97admin.com -all' },
          { id: 'spf-2', type: 'TXT', name: 'example.com', content: 'v=spf1 include:spf.mailjet.com include:spf.97admin.com ip4:192.0.2.10 a:in.example.com -all' }
        ],
        result_info: { page: 2, total_pages: 2 }
      });
    }
    return json({ success: true, result: { id: 'ok' } });
  };

  const result = await applyDnsSetup(domainFixture(), cloudflareCredential(), {
    records: [
      {
        key: 'spf',
        host: 'example.com',
        type: 'TXT',
        value: 'v=spf1 include:spf.mailjet.com include:spf.97admin.com ip4:192.0.2.10 a:in.example.com -all'
      }
    ]
  });

  assert.equal(result.ok, true);
  assert.ok(calls.some((call) => call.url.includes('name.exact=example.com')));
  assert.ok(calls.some((call) => call.method === 'PUT' && call.url.includes('/dns_records/spf-1')));
  assert.ok(calls.some((call) => call.method === 'DELETE' && call.url.includes('/dns_records/spf-2')));
  assert.equal(calls.some((call) => call.method === 'POST'), false);
});

test('aliyun provider signs and sends create/update record actions', async () => {
  const actions = [];
  globalThis.fetch = async (url) => {
    const params = new URL(String(url)).searchParams;
    const action = params.get('Action');
    actions.push(action);
    if (action === 'DescribeDomainRecords') {
      return json({
        DomainRecords: {
          Record: [{ RecordId: '1', RR: '_dmarc', Type: 'TXT', Value: 'v=DMARC1; p=none' }]
        }
      });
    }
    return json({});
  };

  const credential = aliyunCredential();
  assert.equal((await testDnsCredential(credential)).ok, true);
  const result = await applyDnsSetup(domainFixture(), credential, {
    records: [{ key: 'dmarc', host: '_dmarc.example.com', type: 'TXT', value: 'v=DMARC1; p=reject' }]
  });

  assert.equal(result.ok, true);
  assert.ok(actions.includes('UpdateDomainRecord'));
});

test('aliyun one-click dns falls back to parent zone for subdomain sending domains', async () => {
  const calls = [];
  globalThis.fetch = async (url) => {
    const params = new URL(String(url)).searchParams;
    calls.push({
      action: params.get('Action'),
      domainName: params.get('DomainName'),
      rr: params.get('RR')
    });
    if (params.get('DomainName') === 'notify.example.com') {
      return json({
        Code: 'InvalidDomainName.NoExist',
        Message: 'domain not found'
      });
    }
    if (params.get('Action') === 'DescribeDomainRecords') {
      return json({ DomainRecords: { Record: [] } });
    }
    return json({});
  };

  const result = await applyDnsSetup(
    { ...domainFixture(), domain: 'notify.example.com', senderHost: 'smtp.example.com' },
    { ...aliyunCredential(), zoneName: 'notify.example.com' },
    {
      records: [
        {
          key: 'verification',
          host: '_mailhub.notify.example.com',
          type: 'TXT',
          value: 'mailhub-verification=token',
          status: 'missing'
        }
      ]
    }
  );

  assert.equal(result.ok, true);
  assert.ok(calls.some((call) => call.action === 'DescribeDomainRecords' && call.domainName === 'notify.example.com'));
  assert.ok(calls.some((call) => call.action === 'DescribeDomainRecords' && call.domainName === 'example.com'));
  assert.ok(calls.some((call) => (
    call.action === 'AddDomainRecord'
    && call.domainName === 'example.com'
    && call.rr === '_mailhub.notify'
  )));
});

test('dnspod provider signs and sends create record actions', async () => {
  const actions = [];
  globalThis.fetch = async (url, options = {}) => {
    assert.equal(String(url), 'https://dnspod.tencentcloudapi.com');
    actions.push(options.headers['X-TC-Action']);
    if (options.headers['X-TC-Action'] === 'DescribeRecordList') {
      return json({ Response: { RecordList: [] } });
    }
    return json({ Response: { RecordId: 123 } });
  };

  const credential = dnspodCredential();
  assert.equal((await testDnsCredential(credential)).ok, true);
  const result = await applyDnsSetup(domainFixture(), credential, {
    records: [{ key: 'dkim', host: 'mh._domainkey.example.com', type: 'TXT', value: 'v=DKIM1; k=rsa; p=abc' }]
  });

  assert.equal(result.ok, true);
  assert.ok(actions.includes('CreateRecord'));
});

test('dnspod provider treats empty record list responses as no existing records', async () => {
  const actions = [];
  globalThis.fetch = async (url, options = {}) => {
    assert.equal(String(url), 'https://dnspod.tencentcloudapi.com');
    actions.push(options.headers['X-TC-Action']);
    if (options.headers['X-TC-Action'] === 'DescribeRecordList') {
      return json({
        Response: {
          Error: {
            Code: 'FailedOperation.RecordListEmpty',
            Message: '记录列表为空。'
          }
        }
      });
    }
    return json({ Response: { RecordId: 123 } });
  };

  const result = await applyDnsSetup(domainFixture(), dnspodCredential(), {
    records: [{ key: 'dkim', host: 'mh._domainkey.example.com', type: 'TXT', value: 'v=DKIM1; k=rsa; p=abc' }]
  });

  assert.equal(result.ok, true);
  assert.equal(result.results[0].detail, 'created');
  assert.ok(actions.includes('CreateRecord'));
});

test('dnspod one-click dns falls back to parent zone for subdomain sending domains', async () => {
  const calls = [];
  globalThis.fetch = async (url, options = {}) => {
    assert.equal(String(url), 'https://dnspod.tencentcloudapi.com');
    const payload = JSON.parse(options.body);
    calls.push({ action: options.headers['X-TC-Action'], payload });
    if (payload.Domain === 'notify.example.com') {
      return json({
        Response: {
          Error: {
            Code: 'ResourceNotFound.NoDataOfRecord',
            Message: 'domain not found'
          }
        }
      });
    }
    if (options.headers['X-TC-Action'] === 'DescribeRecordList') {
      return json({ Response: { RecordList: [] } });
    }
    return json({ Response: { RecordId: 123 } });
  };

  const result = await applyDnsSetup(
    { ...domainFixture(), domain: 'notify.example.com', senderHost: 'smtp.example.com' },
    { ...dnspodCredential(), zoneName: 'notify.example.com' },
    {
      records: [
        {
          key: 'verification',
          host: '_mailhub.notify.example.com',
          type: 'TXT',
          value: 'mailhub-verification=token',
          status: 'missing'
        }
      ]
    }
  );

  assert.equal(result.ok, true);
  assert.ok(calls.some((call) => call.action === 'DescribeRecordList' && call.payload.Domain === 'notify.example.com'));
  assert.ok(calls.some((call) => call.action === 'DescribeRecordList' && call.payload.Domain === 'example.com'));
  assert.ok(calls.some((call) => (
    call.action === 'CreateRecord'
    && call.payload.Domain === 'example.com'
    && call.payload.SubDomain === '_mailhub.notify'
  )));
});

test('one-click dns setup only applies records under the user domain zone', async () => {
  const calls = [];
  globalThis.fetch = async (url, options = {}) => {
    calls.push({ url: String(url), method: options.method || 'GET' });
    if (String(url).includes('/zones?')) return json({ success: true, result: [{ id: 'zone-1', name: 'example.com' }] });
    if (String(url).includes('/dns_records?')) return json({ success: true, result: [] });
    return json({ success: true, result: { id: 'ok' } });
  };

  const result = await applyDnsSetup(domainFixture(), cloudflareCredential(), {
    records: [
      {
        key: 'dkim',
        host: 'mh._domainkey.example.com',
        type: 'TXT',
        value: 'v=DKIM1; k=rsa; p=abc',
        status: 'missing'
      },
      {
        key: 'sender-a',
        host: 'smtp.example.com',
        type: 'A',
        value: '127.0.0.1',
        status: 'ok'
      }
    ]
  });

  assert.equal(result.ok, true);
  assert.equal(result.results.length, 1);
  assert.equal(result.results[0].key, 'dkim');
  assert.equal(calls.filter((call) => call.method === 'POST').length, 1);
});

test('cloudflare one-click dns can use the current domain zone with a multi-zone token', async () => {
  const calls = [];
  globalThis.fetch = async (url, options = {}) => {
    calls.push({ url: String(url), method: options.method || 'GET' });
    if (String(url).includes('/zones?name=other.com')) {
      return json({ success: true, result: [{ id: 'zone-other', name: 'other.com' }] });
    }
    if (String(url).includes('/dns_records?')) return json({ success: true, result: [] });
    return json({ success: true, result: { id: 'ok' } });
  };

  const result = await applyDnsSetup(
    { ...domainFixture(), domain: 'other.com', senderHost: 'mail.other.com' },
    cloudflareCredential(),
    {
      records: [
        {
          key: 'verification',
          host: '_mailhub.other.com',
          type: 'TXT',
          value: 'mailhub-verification=token',
          status: 'missing'
        }
      ]
    }
  );

  assert.equal(result.ok, true);
  assert.equal(result.results[0].ok, true);
  assert.ok(calls.some((call) => call.url.includes('/zones?name=other.com')));
  assert.ok(calls.some((call) => call.method === 'POST' && call.url.includes('/zones/zone-other/dns_records')));
});

test('cloudflare one-click dns discovers the parent zone for subdomain sending domains', async () => {
  const calls = [];
  globalThis.fetch = async (url, options = {}) => {
    calls.push({ url: String(url), method: options.method || 'GET' });
    if (String(url).includes('/zones?name=sender.example.com')) {
      return json({ success: true, result: [] });
    }
    if (String(url).includes('/zones?name=example.com')) {
      return json({ success: true, result: [{ id: 'zone-example', name: 'example.com' }] });
    }
    if (String(url).includes('/dns_records?')) return json({ success: true, result: [] });
    return json({ success: true, result: { id: 'ok' } });
  };

  const result = await applyDnsSetup(
    { ...domainFixture(), domain: 'sender.example.com', senderHost: 'smtp.example.com' },
    { ...cloudflareCredential(), zoneName: 'example.org' },
    {
      records: [
        {
          key: 'verification',
          host: '_mailhub.sender.example.com',
          type: 'TXT',
          value: 'mailhub-verification=token',
          status: 'missing'
        }
      ]
    }
  );

  assert.equal(result.ok, true);
  assert.equal(result.results[0].ok, true);
  assert.ok(calls.some((call) => call.url.includes('/zones?name=sender.example.com')));
  assert.ok(calls.some((call) => call.url.includes('/zones?name=example.com')));
  assert.ok(calls.some((call) => call.method === 'POST' && call.url.includes('/zones/zone-example/dns_records')));
});

test('cloudflare one-click dns falls back from configured child zone to parent zone', async () => {
  const calls = [];
  globalThis.fetch = async (url, options = {}) => {
    calls.push({ url: String(url), method: options.method || 'GET' });
    if (String(url).includes('/zones?name=notify.example.com')) {
      return json({ success: true, result: [] });
    }
    if (String(url).includes('/zones?name=example.com')) {
      return json({ success: true, result: [{ id: 'zone-example', name: 'example.com' }] });
    }
    if (String(url).includes('/dns_records?')) return json({ success: true, result: [] });
    return json({ success: true, result: { id: 'ok' } });
  };

  const result = await applyDnsSetup(
    { ...domainFixture(), domain: 'notify.example.com', senderHost: 'smtp.example.com' },
    { ...cloudflareCredential(), zoneName: 'notify.example.com' },
    {
      records: [
        {
          key: 'verification',
          host: '_mailhub.notify.example.com',
          type: 'TXT',
          value: 'mailhub-verification=token',
          status: 'missing'
        }
      ]
    }
  );

  assert.equal(result.ok, true);
  assert.equal(result.results[0].ok, true);
  assert.ok(calls.some((call) => call.url.includes('/zones?name=notify.example.com')));
  assert.ok(calls.some((call) => call.url.includes('/zones?name=example.com')));
  assert.ok(calls.some((call) => call.method === 'POST' && call.url.includes('/zones/zone-example/dns_records')));
});

function cloudflareCredential() {
  return {
    provider: 'cloudflare',
    zoneName: 'example.com',
    defaultTtl: 600,
    credentials: { apiToken: 'token' }
  };
}

function aliyunCredential() {
  return {
    provider: 'aliyun',
    zoneName: 'example.com',
    defaultTtl: 600,
    credentials: { accessKeyId: 'id', accessKeySecret: 'secret' }
  };
}

function dnspodCredential() {
  return {
    provider: 'dnspod',
    zoneName: 'example.com',
    defaultTtl: 600,
    credentials: { secretId: 'id', secretKey: 'secret' }
  };
}

function domainFixture() {
  return {
    domain: 'example.com',
    senderHost: 'mail.example.com',
    sendingIp: '127.0.0.1'
  };
}

function json(payload) {
  return {
    ok: true,
    status: 200,
    async json() {
      return payload;
    }
  };
}
