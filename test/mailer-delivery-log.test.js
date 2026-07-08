import assert from 'node:assert/strict';
import net from 'node:net';
import { test } from 'node:test';

import { sendViaSmtp } from '../src/mailer.js';

test('records a sanitized SMTP delivery log without storing credentials or message body', async () => {
  const capturedCommands = [];
  const server = net.createServer((socket) => {
    socket.setEncoding('utf8');
    socket.write('220 relay.test ESMTP ready\r\n');
    let buffer = '';
    let dataMode = false;

    socket.on('data', (chunk) => {
      buffer += chunk;
      let index;
      while ((index = buffer.indexOf('\n')) !== -1) {
        const line = buffer.slice(0, index).replace(/\r$/, '');
        buffer = buffer.slice(index + 1);

        if (dataMode) {
          if (line === '.') {
            dataMode = false;
            socket.write('250 2.0.0 queued as ABC123\r\n');
          }
          continue;
        }

        capturedCommands.push(line);
        if (line.startsWith('EHLO')) {
          socket.write('250-relay.test\r\n250 AUTH PLAIN\r\n');
        } else if (line.startsWith('AUTH PLAIN')) {
          socket.write('235 2.7.0 authentication successful\r\n');
        } else if (line.startsWith('MAIL FROM')) {
          socket.write('250 2.1.0 sender ok\r\n');
        } else if (line.startsWith('RCPT TO')) {
          socket.write('250 2.1.5 recipient ok\r\n');
        } else if (line === 'DATA') {
          dataMode = true;
          socket.write('354 end with dot\r\n');
        } else if (line === 'QUIT') {
          socket.write('221 bye\r\n');
          socket.end();
        }
      }
    });
  });

  await listen(server);
  try {
    const { port } = server.address();
    const result = await sendViaSmtp({
      host: '127.0.0.1',
      port,
      secure: false,
      username: 'smtp-user',
      password: 'super-secret',
      helo: 'mail.example.com',
      mailFrom: 'sender@example.com',
      recipients: ['rcpt@example.net'],
      rawMessage: 'Subject: Private\r\n\r\nThis body must not be logged'
    });

    assert.equal(result.code, 250);
    assert.equal(result.queueId, 'ABC123');
    assert.ok(Array.isArray(result.deliveryLog));
    assert.ok(result.deliveryLog.length >= 10);

    const serialized = JSON.stringify(result.deliveryLog);
    assert.match(serialized, /EHLO mail\.example\.com/);
    assert.match(serialized, /AUTH PLAIN <redacted>/);
    assert.match(serialized, /MAIL FROM:<sender@example\.com>/);
    assert.match(serialized, /RCPT TO:<rcpt@example\.net>/);
    assert.match(serialized, /DATA/);
    assert.match(serialized, /queued as ABC123/);
    assert.match(serialized, /messageBytes/);
    assert.doesNotMatch(serialized, /super-secret/);
    assert.doesNotMatch(serialized, /This body must not be logged/);

    assert.ok(capturedCommands.some((command) => command.startsWith('AUTH PLAIN ')));
  } finally {
    await close(server);
  }
});

function listen(server) {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      server.off('error', reject);
      resolve();
    });
  });
}

function close(server) {
  return new Promise((resolve) => server.close(resolve));
}
