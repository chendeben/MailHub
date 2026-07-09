import assert from 'node:assert/strict';
import dns from 'node:dns';
import { test } from 'node:test';

test('includes live current values for verification and dkim records', async () => {
  const originalResolver = dns.promises.Resolver;
  const lookup = new Map([
    ['example.com', ['v=spf1 ip4:192.0.2.10 a:mail.example.com ~all']],
    ['_mailhub.example.com', ['mailhub-verification=verify-token']],
    ['mh202607._domainkey.example.com', ['v=DKIM1; k=rsa; p=dkim-public']],
    ['_dmarc.example.com', ['v=DMARC1; p=none; rua=mailto:dmarc@example.com; adkim=s; aspf=s; pct=100']]
  ]);

  dns.promises.Resolver = class FakeResolver {
    setServers() {}

    async resolveTxt(name) {
      const value = lookup.get(name);
      if (!value) {
        const error = new Error('not found');
        error.code = 'ENODATA';
        throw error;
      }
      return value.map((record) => [record]);
    }

    async resolve4(name) {
      return name === 'mail.example.com' ? ['192.0.2.10'] : [];
    }

    async reverse(ip) {
      return ip === '192.0.2.10' ? ['mail.example.com'] : [];
    }
  };

  try {
    const { buildDnsGuide } = await import(`../src/dns-guide.js?test=${Date.now()}`);
    const guide = await buildDnsGuide({
      domain: 'example.com',
      selector: 'mh202607',
      verificationToken: 'verify-token',
      dkimPublic: 'dkim-public',
      senderHost: 'mail.example.com',
      sendingIp: '192.0.2.10',
      spfExtra: '',
      dmarcPolicy: 'none',
      dmarcRua: 'mailto:dmarc@example.com'
    });

    const verification = guide.records.find((record) => record.key === 'verification');
    const dkim = guide.records.find((record) => record.key === 'dkim');

    assert.equal(guide.records.some((record) => record.key === 'ptr'), false);
    assert.deepEqual(verification.current, ['mailhub-verification=verify-token']);
    assert.deepEqual(dkim.current, ['v=DKIM1; k=rsa; p=dkim-public']);
  } finally {
    dns.promises.Resolver = originalResolver;
  }
});

test('builds PTR as a system delivery check', async () => {
  const originalResolver = dns.promises.Resolver;

  dns.promises.Resolver = class FakeResolver {
    setServers() {}
    async reverse(ip) {
      return ip === '192.0.2.10' ? ['mail.example.com'] : [];
    }
  };

  try {
    const { buildSystemDnsChecks } = await import(`../src/dns-guide.js?test=${Date.now()}-system`);
    const checks = await buildSystemDnsChecks({
      mailHostname: 'mail.example.com',
      sendingIp: '192.0.2.10'
    });

    assert.equal(checks.ptr.key, 'ptr');
    assert.equal(checks.ptr.host, '192.0.2.10');
    assert.equal(checks.ptr.value, 'mail.example.com');
    assert.equal(checks.ptr.status, 'ok');
    assert.deepEqual(checks.ptr.current, ['mail.example.com']);
  } finally {
    dns.promises.Resolver = originalResolver;
  }
});
