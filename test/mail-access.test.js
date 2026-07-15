import assert from 'node:assert/strict';
import { mkdtempSync } from 'node:fs';
import net from 'node:net';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { test } from 'node:test';

import {
  createDomain,
  createInboundMailbox,
  createInboundMessage,
  createUser,
  initDatabase,
  listInboundMessages
} from '../src/db.js';
import { startMailboxAccessServers } from '../src/mail-access.js';

test('IMAP clients can log in and fetch mailbox messages', async () => {
  initDatabase(mkdtempSync(path.join(tmpdir(), 'mailhub-imap-test-')), 'mail-access-secret');
  const { user, mailbox } = createMailboxFixture('imap.example', 'imap-user');
  createInboundMessage(mailbox, {
    sender: 'alice@example.net',
    recipients: ['admin@imap.example'],
    subject: 'IMAP hello',
    messageId: '<imap-hello@example.net>',
    rawMessage: [
      'From: Alice <alice@example.net>',
      'To: admin@imap.example',
      'Subject: IMAP hello',
      'Message-ID: <imap-hello@example.net>',
      '',
      'Hello through IMAP.'
    ].join('\r\n'),
    textBody: 'Hello through IMAP.'
  });

  const [server] = startMailboxAccessServers({
    hostname: 'mail.imap.example',
    imapEnabled: true,
    imapListeners: [{ port: 0, protocol: 'imap' }],
    pop3Enabled: false,
    pop3Listeners: [],
    allowInsecureAuth: true
  });
  await waitForListening(server);

  try {
    const port = server.address().port;
    const client = await connectClient(port);
    await client.readUntil(/\* OK .* IMAP ready\r\n/);
    assert.match(await client.command('A1 LOGIN "admin@imap.example" "mailbox-pass-123"', /A1 OK/), /LOGIN completed/);
    const selected = await client.command('A2 SELECT INBOX', /A2 OK/);
    assert.match(selected, /\* 1 EXISTS/);
    const fetched = await client.command('A3 UID FETCH 1:* (UID FLAGS RFC822.SIZE BODY.PEEK[])', /A3 OK/);
    assert.match(fetched, /\* 1 FETCH/);
    assert.match(fetched, /UID 1/);
    assert.match(fetched, /Subject: IMAP hello/);
    assert.match(fetched, /Hello through IMAP\./);
    await client.command('A4 LOGOUT', /A4 OK/);
    client.close();
    assert.equal(listInboundMessages(user.id).length, 1);
  } finally {
    await closeServer(server);
  }
});

test('IMAP exposes MIME body structures and individual parts for Roundcube', async () => {
  initDatabase(mkdtempSync(path.join(tmpdir(), 'mailhub-imap-mime-test-')), 'mail-access-secret');
  const { mailbox } = createMailboxFixture('mime.example', 'mime-user');
  createInboundMessage(mailbox, {
    sender: 'alice@example.net',
    recipients: ['admin@mime.example'],
    subject: 'MIME message',
    messageId: '<mime-message@example.net>',
    rawMessage: [
      'From: Alice <alice@example.net>',
      'To: admin@mime.example',
      'Subject: MIME message',
      'MIME-Version: 1.0',
      'Content-Type: multipart/alternative; boundary="mailhub-boundary"',
      '',
      '--mailhub-boundary',
      'Content-Type: text/plain; charset=UTF-8',
      'Content-Transfer-Encoding: quoted-printable',
      '',
      'Plain message body.',
      '--mailhub-boundary',
      'Content-Type: text/html; charset=UTF-8',
      '',
      '<p>HTML message body.</p>',
      '--mailhub-boundary--',
      ''
    ].join('\r\n'),
    textBody: 'Plain message body.',
    htmlBody: '<p>HTML message body.</p>'
  });

  const [server] = startMailboxAccessServers({
    hostname: 'mail.mime.example',
    imapEnabled: true,
    imapListeners: [{ port: 0, protocol: 'imap' }],
    pop3Enabled: false,
    pop3Listeners: [],
    allowInsecureAuth: true
  });
  await waitForListening(server);

  let client;
  try {
    client = await connectClient(server.address().port);
    await client.readUntil(/\* OK .* IMAP ready\r\n/);
    assert.match(await client.command('A1 LOGIN "admin@mime.example" "mailbox-pass-123"', /A1 OK/), /LOGIN completed/);
    await client.command('A2 SELECT INBOX', /A2 OK/);

    const structure = await client.command('A3 UID FETCH 1 (UID BODYSTRUCTURE)', /A3 OK/);
    assert.match(structure, /BODYSTRUCTURE \(\("TEXT" "PLAIN" \("CHARSET" "UTF-8"\)/);
    assert.match(structure, /"HTML" \("CHARSET" "UTF-8"\).*"ALTERNATIVE" \("BOUNDARY" "mailhub-boundary"\)\)/);

    const textPart = await client.command('A4 UID FETCH 1 (BODY.PEEK[1])', /A4 OK/);
    assert.match(textPart, /BODY\[1\] \{\d+\}\r\nPlain message body\./);
    assert.doesNotMatch(textPart, /Content-Type: text\/plain/);

    const htmlPart = await client.command('A5 UID FETCH 1 (BODY.PEEK[2])', /A5 OK/);
    assert.match(htmlPart, /BODY\[2\] \{\d+\}\r\n<p>HTML message body\.<\/p>/);

    const mimeHeaders = await client.command('A6 UID FETCH 1 (BODY.PEEK[1.MIME])', /A6 OK/);
    assert.match(mimeHeaders, /BODY\[1\.MIME\] \{\d+\}\r\nContent-Type: text\/plain; charset=UTF-8/);
    await client.command('A7 LOGOUT', /A7 OK/);
    client.close();
  } finally {
    client?.close();
    await closeServer(server);
  }
});

test('IMAP exposes standard folders expected by mainstream clients', async () => {
  initDatabase(mkdtempSync(path.join(tmpdir(), 'mailhub-imap-folders-test-')), 'mail-access-secret');
  createMailboxFixture('folders.example', 'folders-user');

  const [server] = startMailboxAccessServers({
    hostname: 'mail.folders.example',
    imapEnabled: true,
    imapListeners: [{ port: 0, protocol: 'imap' }],
    pop3Enabled: false,
    pop3Listeners: [],
    allowInsecureAuth: true
  });
  await waitForListening(server);

  let client;
  try {
    client = await connectClient(server.address().port);
    await client.readUntil(/\* OK .* IMAP ready\r\n/);
    assert.match(await client.command('A1 LOGIN "admin@folders.example" "mailbox-pass-123"', /A1 OK/), /LOGIN completed/);

    const listed = await client.command('A2 LIST "" "*"', /A2 OK/);
    assert.match(listed, /\* LIST .* "INBOX"/);
    assert.match(listed, /\* LIST .*\\Sent.* "Sent"/);
    assert.match(listed, /\* LIST .*\\Drafts.* "Drafts"/);
    assert.match(listed, /\* LIST .*\\Trash.* "Trash"/);
    assert.match(listed, /\* LIST .*\\Junk.* "Junk"/);
    assert.match(listed, /\* LIST .*\\Archive.* "Archive"/);

    const selected = await client.command('A3 SELECT Sent', /A3 OK/);
    assert.match(selected, /\* 0 EXISTS/);
    await client.command('A4 LOGOUT', /A4 OK/);
    client.close();
  } finally {
    client?.close();
    await closeServer(server);
  }
});

test('IMAP APPEND stores sent messages in the Sent folder', async () => {
  initDatabase(mkdtempSync(path.join(tmpdir(), 'mailhub-imap-append-test-')), 'mail-access-secret');
  createMailboxFixture('append.example', 'append-user');

  const [server] = startMailboxAccessServers({
    hostname: 'mail.append.example',
    imapEnabled: true,
    imapListeners: [{ port: 0, protocol: 'imap' }],
    pop3Enabled: false,
    pop3Listeners: [],
    allowInsecureAuth: true
  });
  await waitForListening(server);

  let client;
  try {
    const sentMessage = [
      'From: Admin <admin@append.example>',
      'To: Bob <bob@example.net>',
      'Subject: Sent copy',
      'Message-ID: <sent-copy@append.example>',
      '',
      'This copy belongs in Sent.'
    ].join('\r\n');

    client = await connectClient(server.address().port);
    await client.readUntil(/\* OK .* IMAP ready\r\n/);
    assert.match(await client.command('A1 LOGIN "admin@append.example" "mailbox-pass-123"', /A1 OK/), /LOGIN completed/);
    await client.append(`A2 APPEND Sent (\\Seen) {${Buffer.byteLength(sentMessage, 'utf8')}}`, sentMessage, /A2 OK/);

    const selectedSent = await client.command('A3 SELECT Sent', /A3 OK/);
    assert.match(selectedSent, /\* 1 EXISTS/);
    const fetchedSent = await client.command('A4 UID FETCH 1:* (UID FLAGS BODY.PEEK[])', /A4 OK/);
    assert.match(fetchedSent, /FLAGS \(\\Seen\)/);
    assert.match(fetchedSent, /Subject: Sent copy/);
    assert.match(fetchedSent, /This copy belongs in Sent\./);

    const selectedInbox = await client.command('A5 SELECT INBOX', /A5 OK/);
    assert.match(selectedInbox, /\* 0 EXISTS/);
    await client.command('A6 LOGOUT', /A6 OK/);
    client.close();
  } finally {
    client?.close();
    await closeServer(server);
  }
});

test('POP3 clients can retrieve and delete messages on quit', async () => {
  initDatabase(mkdtempSync(path.join(tmpdir(), 'mailhub-pop3-test-')), 'mail-access-secret');
  const { user, mailbox } = createMailboxFixture('pop3.example', 'pop3-user');
  createInboundMessage(mailbox, {
    sender: 'bob@example.net',
    recipients: ['admin@pop3.example'],
    subject: 'POP3 hello',
    messageId: '<pop3-hello@example.net>',
    rawMessage: [
      'From: Bob <bob@example.net>',
      'To: admin@pop3.example',
      'Subject: POP3 hello',
      'Message-ID: <pop3-hello@example.net>',
      '',
      'Hello through POP3.'
    ].join('\r\n'),
    textBody: 'Hello through POP3.'
  });

  const [server] = startMailboxAccessServers({
    hostname: 'mail.pop3.example',
    imapEnabled: false,
    imapListeners: [],
    pop3Enabled: true,
    pop3Listeners: [{ port: 0, protocol: 'pop3' }],
    allowInsecureAuth: true
  });
  await waitForListening(server);

  try {
    const client = await connectClient(server.address().port);
    await client.readUntil(/\+OK .* POP3 ready\r\n/);
    assert.match(await client.command('USER admin@pop3.example', /\+OK/), /User accepted/);
    assert.match(await client.command('PASS mailbox-pass-123', /\+OK/), /ready/);
    assert.match(await client.command('STAT', /\+OK \d+ \d+/), /\+OK 1 /);
    assert.match(await client.command('UIDL 1', /\+OK 1 mh-1/), /\+OK 1 mh-1/);
    const retrieved = await client.command('RETR 1', /\r\n\.\r\n/);
    assert.match(retrieved, /Subject: POP3 hello/);
    assert.match(retrieved, /Hello through POP3\./);
    assert.match(await client.command('DELE 1', /\+OK/), /deleted/);
    await client.command('QUIT', /\+OK Bye/);
    client.close();
    assert.equal(listInboundMessages(user.id).length, 0);
  } finally {
    await closeServer(server);
  }
});

function createMailboxFixture(domainName, username) {
  const user = createUser({ username, email: `${username}@example.com`, password: 'password123' });
  createDomain(user.id, {
    domain: domainName,
    selector: 'mh',
    verificationToken: 'verify',
    dkimPublic: 'public',
    dkimPrivate: 'private',
    senderHost: `mail.${domainName}`,
    sendingIp: '192.0.2.30',
    spfExtra: '',
    dmarcPolicy: 'none',
    dmarcRua: ''
  });
  const mailbox = createInboundMailbox(user.id, {
    address: `admin@${domainName}`,
    password: 'mailbox-pass-123'
  });
  return { user, mailbox };
}

function connectClient(port) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ host: '127.0.0.1', port });
    socket.setEncoding('utf8');
    socket.setTimeout(5000);
    let buffer = '';
    const waiters = [];

    socket.on('data', (chunk) => {
      buffer += chunk;
      for (const waiter of [...waiters]) {
        if (waiter.pattern.test(buffer)) {
          waiters.splice(waiters.indexOf(waiter), 1);
          const output = buffer;
          buffer = '';
          waiter.resolve(output);
        }
      }
    });
    socket.once('connect', () => resolve({
      command(command, pattern) {
        socket.write(`${command}\r\n`);
        return this.readUntil(pattern);
      },
      async append(command, literal, pattern) {
        socket.write(`${command}\r\n`);
        await this.readUntil(/^\+ /m);
        socket.write(`${literal}\r\n`);
        return this.readUntil(pattern);
      },
      readUntil(pattern) {
        if (pattern.test(buffer)) {
          const output = buffer;
          buffer = '';
          return Promise.resolve(output);
        }
        return new Promise((waitResolve, waitReject) => {
          const waiter = {
            pattern,
            resolve(output) {
              clearTimeout(waiter.timer);
              waitResolve(output);
            },
            reject(error) {
              clearTimeout(waiter.timer);
              waitReject(error);
            },
            timer: null
          };
          waiter.timer = setTimeout(() => {
            waiters.splice(waiters.indexOf(waiter), 1);
            waitReject(new Error(`Timed out waiting for ${pattern}; buffered response: ${buffer}`));
          }, 5000);
          waiters.push(waiter);
        });
      },
      close() {
        socket.destroy();
      }
    }));
    socket.once('error', reject);
    socket.once('timeout', () => reject(new Error('Mail access client timed out')));
  });
}

function waitForListening(server) {
  if (server.listening) return Promise.resolve();
  return new Promise((resolve) => server.once('listening', resolve));
}

function closeServer(server) {
  return new Promise((resolve, reject) => {
    server.close((error) => error ? reject(error) : resolve());
  });
}
