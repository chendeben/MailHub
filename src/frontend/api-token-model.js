export function canCopyFullApiToken(token = {}) {
  return Boolean(token.token);
}

export function getCreatedApiTokenSecret(token = {}) {
  return canCopyFullApiToken(token) ? String(token.token) : '';
}

export function getCopyableApiToken(token = {}) {
  return getCreatedApiTokenSecret(token);
}

export function formatApiTokenPrefix(token = {}) {
  return token.tokenPrefix ? `${token.tokenPrefix}...` : '-';
}

export function buildApiUsageExamples({
  endpoint = '/api/send',
  token = '<USER_API_TOKEN>',
  from = 'noreply@example.com',
  to = 'user@example.com'
} = {}) {
  const body = {
    from,
    to,
    subject: 'Hello from MailHub',
    text: 'Signed with DKIM and queued by MailHub.'
  };
  const requestBody = JSON.stringify(body, null, 2);

  return {
    requestBody,
    successResponse: JSON.stringify({
      queued: true,
      domain: domainFromAddress(from) || 'example.com',
      recipients: [to],
      smtp: 'Message queued'
    }, null, 2),
    curl: `curl -X POST ${endpoint} \\
  -H 'Authorization: Bearer ${token}' \\
  -H 'Content-Type: application/json' \\
  -d '${requestBody}'`,
    nodeFetch: `const response = await fetch('${endpoint}', {
  method: 'POST',
  headers: {
    Authorization: 'Bearer ${token}',
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({
    from: '${from}',
    to: '${to}',
    subject: 'Hello from MailHub',
    text: 'Signed with DKIM and queued by MailHub.'
  })
});

const result = await response.json();`
  };
}

function domainFromAddress(value) {
  return String(value || '').split('@')[1] || '';
}
