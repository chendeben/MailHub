import {
  buildMessage,
  extractAddress,
  parseAddressList,
  sendViaSmtp as smtpSendViaSmtp
} from './mailer.js';

export function buildVerificationEmail({ appBaseUrl, to, token, fromEmail, fromName }) {
  const verifyUrl = accountUrl(appBaseUrl, '/api/auth/verify-email', token);
  return {
    from: formatSender(fromEmail, fromName),
    to,
    subject: '验证邮箱 - MailHub',
    text: [
      '请点击下面的链接验证你的邮箱：',
      '',
      verifyUrl,
      '',
      '验证后账号会进入管理员审核流程。'
    ].join('\n')
  };
}

export function buildPasswordResetEmail({ appBaseUrl, to, token, fromEmail, fromName }) {
  const resetUrl = accountUrl(appBaseUrl, '/reset-password', token);
  return {
    from: formatSender(fromEmail, fromName),
    to,
    subject: '重置密码 - MailHub',
    text: [
      '请点击下面的链接重置你的密码：',
      '',
      resetUrl,
      '',
      '如果不是你本人发起的请求，可以忽略这封邮件。'
    ].join('\n')
  };
}

export async function sendSystemEmail(settings, message, { sendViaSmtp = smtpSendViaSmtp } = {}) {
  const from = message.from || formatSender(settings.fromEmail, settings.fromName);
  const recipients = normalizeRecipients(message.to);
  const rawMessage = buildMessage({
    from,
    to: recipients,
    subject: message.subject,
    text: message.text,
    html: message.html,
    baseUrl: settings.appBaseUrl
  });
  try {
    const result = await sendViaSmtp({
      host: settings.host,
      port: settings.port,
      secure: settings.secure,
      username: settings.username,
      password: settings.password,
      helo: settings.helo,
      mailFrom: extractAddress(settings.fromEmail || from),
      recipients,
      rawMessage
    });
    return {
      ok: true,
      code: result.code,
      message: result.message,
      queueId: result.queueId || ''
    };
  } catch (error) {
    return {
      ok: false,
      message: error.message
    };
  }
}

function accountUrl(appBaseUrl, pathname, token) {
  const base = String(appBaseUrl || '').replace(/\/+$/, '') || 'http://127.0.0.1:3000';
  return `${base}${pathname}?token=${encodeURIComponent(token || '')}`;
}

function formatSender(fromEmail, fromName) {
  const email = extractAddress(fromEmail);
  const name = String(fromName || '').replace(/["\r\n]+/g, ' ').trim();
  if (!name) return email;
  return `"${name}" <${email}>`;
}

function normalizeRecipients(value) {
  const items = Array.isArray(value) ? value : parseAddressList(value);
  return items
    .map((item) => (/[\r\n]/.test(String(item || '')) ? '' : extractAddress(item)))
    .filter(Boolean);
}
