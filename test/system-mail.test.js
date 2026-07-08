import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  buildPasswordResetEmail,
  buildVerificationEmail,
  sendSystemEmail
} from '../src/system-mail.js';

test('builds verification email with configured sender and verification url', () => {
  const message = buildVerificationEmail({
    appBaseUrl: 'https://mail.example.com/',
    to: 'alice@example.com',
    token: 'verify-token',
    fromEmail: 'notify@example.com',
    fromName: 'MailHub Notify'
  });

  assert.equal(message.from, '"MailHub Notify" <notify@example.com>');
  assert.equal(message.to, 'alice@example.com');
  assert.match(message.subject, /验证邮箱/);
  assert.match(message.text, /https:\/\/mail\.example\.com\/api\/auth\/verify-email\?token=verify-token/);
});

test('builds password reset email with reset url', () => {
  const message = buildPasswordResetEmail({
    appBaseUrl: 'https://mail.example.com',
    to: 'alice@example.com',
    token: 'reset-token',
    fromEmail: 'notify@example.com',
    fromName: ''
  });

  assert.equal(message.from, 'notify@example.com');
  assert.match(message.subject, /重置密码/);
  assert.match(message.text, /https:\/\/mail\.example\.com\/reset-password\?token=reset-token/);
});

test('sends system email through smtp without returning secrets', async () => {
  let sentPayload;
  const result = await sendSystemEmail({
    host: 'smtp.example.com',
    port: 465,
    secure: true,
    username: 'mailer@example.com',
    password: 'smtp-password-123',
    helo: 'mail.example.com',
    fromEmail: 'notify@example.com',
    fromName: 'MailHub Notify'
  }, buildVerificationEmail({
    appBaseUrl: 'https://mail.example.com',
    to: 'alice@example.com',
    token: 'verify-token',
    fromEmail: 'notify@example.com',
    fromName: 'MailHub Notify'
  }), {
    sendViaSmtp: async (payload) => {
      sentPayload = payload;
      return {
        code: 250,
        message: '2.0.0 queued as ABC123',
        queueId: 'ABC123',
        deliveryLog: [{
          phase: 'auth',
          direction: 'client',
          command: 'AUTH PLAIN <redacted>'
        }]
      };
    }
  });

  assert.equal(sentPayload.host, 'smtp.example.com');
  assert.equal(sentPayload.port, 465);
  assert.equal(sentPayload.secure, true);
  assert.equal(sentPayload.username, 'mailer@example.com');
  assert.equal(sentPayload.password, 'smtp-password-123');
  assert.equal(sentPayload.helo, 'mail.example.com');
  assert.equal(sentPayload.mailFrom, 'notify@example.com');
  assert.deepEqual(sentPayload.recipients, ['alice@example.com']);
  assert.match(sentPayload.rawMessage, /^From: "MailHub Notify" <notify@example.com>/);

  assert.deepEqual(result, {
    ok: true,
    code: 250,
    message: '2.0.0 queued as ABC123',
    queueId: 'ABC123'
  });
  assert.equal(JSON.stringify(result).includes('smtp-password-123'), false);
  assert.equal(JSON.stringify(result).includes('verify-token'), false);
});

test('normalizes array recipients before building smtp payload', async () => {
  let sentPayload;
  await sendSystemEmail({
    host: 'smtp.example.com',
    port: 25,
    secure: false,
    username: '',
    password: '',
    helo: 'mail.example.com',
    fromEmail: 'notify@example.com',
    fromName: 'MailHub Notify'
  }, {
    from: '"MailHub Notify" <notify@example.com>',
    to: ['Alice <alice@example.com>', 'bad\r\nRCPT TO:<evil@example.com>'],
    subject: '安全测试',
    text: 'Hello'
  }, {
    sendViaSmtp: async (payload) => {
      sentPayload = payload;
      return { code: 250, message: 'queued', queueId: 'SAFE' };
    }
  });

  assert.deepEqual(sentPayload.recipients, ['alice@example.com']);
  assert.match(sentPayload.rawMessage, /^To: alice@example.com$/m);
  assert.doesNotMatch(sentPayload.rawMessage, /^Bcc:/m);
  assert.doesNotMatch(sentPayload.rawMessage, /RCPT TO/i);
});
