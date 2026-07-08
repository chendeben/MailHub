import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync } from 'node:fs';
import net from 'node:net';
import { tmpdir } from 'node:os';
import path from 'node:path';
import tls from 'node:tls';
import { test } from 'node:test';

import { startSubmissionServer } from '../src/submission.js';

const testCert = `-----BEGIN CERTIFICATE-----
MIIDCTCCAfGgAwIBAgIUKFK3kjPk5eJZ2nsmLbEjfQZp5lQwDQYJKoZIhvcNAQEL
BQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MDcwODA2MjYzMloXDTI2MDgw
NzA2MjYzMlowFDESMBAGA1UEAwwJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEAuUOQ0ewpBEjMNEBcyN79o8ujqetpWh7wbLcc5+aiNUaa
OhmGitZaHuNzLBG/vhd44QJjBmdRV4lG8/t8NCFMczpHzmW5f8ovY+5MqeOMDXDX
zeX+LjyraYTM/NxuZirUOQNjE5oq5T8TirTpp1ZycF/aYz9kyq/BlIR3bMySHV+M
39o6U1aS71tpP4NthnwOtxWs9Md5axfw5d4PcNEbEx42XfcQxnaZkmIm3O0uQ9z/
E5K9TwMPsIAYVWKUff57thwB27cj/SBEJoPCAcWvIenbPddLGuIm+T9LHoGiMmfd
OSW9Hx+1fKCAsIA9JuUkMCCRWAnI6aft+gI+GByFVQIDAQABo1MwUTAdBgNVHQ4E
FgQUEBUJl3WRWbTyqk1gF9T0tpPQGx8wHwYDVR0jBBgwFoAUEBUJl3WRWbTyqk1g
F9T0tpPQGx8wDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAOsr+
ZBjxA+3ynvE0Ay0UHVNKWmkkxVwX9uiYdfP/KZSD8HGuEZ22c9Z4EmfLg4XxXnaK
Up2A3vg/r1TA4LcHSCzCpYgUsT1mNs84jFlkg7qcSr/To3AodQIbU6290nVIHCoA
LLLpDLOMm7HkrbqRRQnLJBz296PZgHZDZ5W680C+QEZhw3BlY6hixdvHikd9xPFv
jBVQrMyBu0kqlhGY3ZsqhMfapn1x/pmCl+kd6KXj5jOn1gSqig4hOh8mGa7xq7D8
/okZ4boyv18n95yjo2YkhpuTidocBDsSoK9U4UQrVl4ID+zydh2vVpvYbCemmBc9
EZVyHdaIa3874ry3Kw==
-----END CERTIFICATE-----`;

const testKey = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC5Q5DR7CkESMw0
QFzI3v2jy6Op62laHvBstxzn5qI1Rpo6GYaK1loe43MsEb++F3jhAmMGZ1FXiUbz
+3w0IUxzOkfOZbl/yi9j7kyp44wNcNfN5f4uPKtphMz83G5mKtQ5A2MTmirlPxOK
tOmnVnJwX9pjP2TKr8GUhHdszJIdX4zf2jpTVpLvW2k/g22GfA63Faz0x3lrF/Dl
3g9w0RsTHjZd9xDGdpmSYibc7S5D3P8Tkr1PAw+wgBhVYpR9/nu2HAHbtyP9IEQm
g8IBxa8h6ds910sa4ib5P0segaIyZ905Jb0fH7V8oICwgD0m5SQwIJFYCcjpp+36
Aj4YHIVVAgMBAAECggEAEPWDqgfHiG4ejVDv/W5WQxp22KzlV7vZz+XiRkM5SY21
PAjOpWJyXP3+ssPMLNtKtDRK+tDV5CC7p0V37PC4ZhrpbFYpCS7psCjmCS48iZVx
F9bMMhDZMx9WQXZvP7h/dVmfRfHYp+QihpHBitExyCIqJGgu8pPssUsAAKxoWrpW
z2VvWXBvIBtvWTJNjBduKgoEAWpqdJU/YlXyDyHKOtGpQEksR4A0CWeMEa4BYgog
MYou8TSiKuIb4M5BKdiHBSO7RiTn6YJ3o7BoGnMVztOPQS6HjMZbAc9oevM2CXQI
4gy/BgqSRz4FFbGDp5ZscRdEgf4sxvmXiIzWQ0jqSQKBgQDg35FCOmMTIBujh0s1
E0D8wmX/Gt6D63Tn1ORFn0OrOSV3qywb9xuQ3ZpSkQwX5+AwjRIcvB1HUTml5xJb
cIxKom/DmCzsHl3Pi16F5U7kRLV0h++Wi4z5Inqdf1jchcPiVwPMZFd0sRwechdr
47PUJokwDb4YQuKGzMJDB/4uWQKBgQDS6G59Gc2dS04BXpSjPcY75JzQ8PIQdOgn
oGdSOhr26hMHIuquHcxTmgLQVDJ1zdNMW6o+btYmGbq3kC25T0JtFn/xVN4kGGSt
askSeC3wuoScRmQbC4ibriXtDI0rVVoW+q9PPxqjnCYumgAru8JPk//sF1OrOcgf
fg4NQeNHXQKBgBReK5oED9U7o0U8i+NSyyAZu4NPu7fXK8+TyNlFg6uOkYY1Stl9
mFGWwNOZr666oePD41AW+c/r23zbYR5HI23fKKBeuDLqzTRvOzCFhI/IaWcUqO7J
1Qr7xH9feXz/4K4vk3h/3iwDnrhjPRvYlAEzPFnN5NnttPbgtPe9UZiBAoGADHoN
lz8Ah+6dhb03o9SStpZWpJGscEbKORXnJtkjITpFt+Vb5sMChGuXAQYKGif7+Qdv
MdRSvNxGzHcuDUlgD54GIZu4rH/47L1leb88UIJoN+p+H492HGeX/McCTu70rmlU
F6cPB2DEbXtUyUGJRDXoLOpQW8/GQ/6sDCK6tE0CgYEAqYZuCqT+mcuZLwwUzQD+
6Yucas5RNEXuBP+2/VjKLjUoNRmI1G3EvLVXtlhw5PFxXqUnNFoaQZ0LEqeNfhrh
pBFgyA7DS+r2vSQNq52yjyyI6Jhe7dIc6I79e3uqSYQ0ODWm5z8IYzmQ64R/yeqb
2trVak9Z2+qu6bsdcDk6TEE=
-----END PRIVATE KEY-----`;

test('smtp listeners accept both plain SMTP and implicit TLS clients', async () => {
  const dataDir = mkdtempSync(path.join(tmpdir(), 'mailhub-submission-test-'));
  const certPath = path.join(dataDir, 'cert.pem');
  const keyPath = path.join(dataDir, 'key.pem');
  writeFileSync(certPath, testCert);
  writeFileSync(keyPath, testKey);
  const [server] = startSubmissionServer({
    enabled: true,
    listeners: [{ port: 0, protocol: 'smtp' }],
    hostname: 'localhost',
    allowInsecureAuth: true,
    tlsCertPath: certPath,
    tlsKeyPath: keyPath
  });
  await waitForListening(server);
  const port = server.address().port;

  try {
    const plainBanner = await readPlainBanner(port);
    assert.match(plainBanner, /^220 localhost MailHub SMTP ready/);

    const tlsBanner = await readImplicitTlsBanner(port);
    assert.match(tlsBanner, /^220 localhost MailHub SMTP ready/);
  } finally {
    await closeServer(server);
  }
});

function waitForListening(server) {
  if (server.listening) return Promise.resolve();
  return new Promise((resolve) => server.once('listening', resolve));
}

function closeServer(server) {
  return new Promise((resolve, reject) => {
    server.close((error) => error ? reject(error) : resolve());
  });
}

function readPlainBanner(port) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ host: '127.0.0.1', port });
    socket.setTimeout(3000);
    socket.once('data', (chunk) => {
      socket.end();
      resolve(chunk.toString('utf8').trim());
    });
    socket.once('error', reject);
    socket.once('timeout', () => reject(new Error('plain SMTP banner timed out')));
  });
}

function readImplicitTlsBanner(port) {
  return new Promise((resolve, reject) => {
    const socket = tls.connect({
      host: '127.0.0.1',
      port,
      rejectUnauthorized: false,
      servername: 'localhost'
    });
    socket.setTimeout(3000);
    socket.once('secureConnect', () => {
      socket.once('data', (chunk) => {
        socket.end();
        resolve(chunk.toString('utf8').trim());
      });
    });
    socket.once('error', reject);
    socket.once('timeout', () => reject(new Error('implicit TLS SMTP banner timed out')));
  });
}
