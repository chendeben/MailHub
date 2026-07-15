import net from 'node:net';
import tls from 'node:tls';
import { readFileSync } from 'node:fs';
import {
  STANDARD_INBOUND_FOLDERS,
  createInboundFolder,
  createInboundMessage,
  inboundFolderExists,
  listInboundFolders,
  listInboundMailboxProtocolMessages,
  markInboundMessageRead,
  softDeleteInboundMessages,
  verifyInboundMailboxCredential
} from './db.js';

export function startMailboxAccessServers(config) {
  const tlsMaterial = loadTlsMaterial(config);
  return [
    ...startProtocolServers('imap', config.imapEnabled, config.imapListeners, config, tlsMaterial),
    ...startProtocolServers('pop3', config.pop3Enabled, config.pop3Listeners, config, tlsMaterial)
  ];
}

export function parseMailboxAccessListeners(value, fallback) {
  return String(value || fallback || '')
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean)
    .map((item) => {
      const [portRaw, protocolRaw = ''] = item.split(':');
      const port = Number(portRaw);
      const protocol = protocolRaw.toLowerCase();
      if (!Number.isInteger(port) || port <= 0 || port > 65535) return null;
      if (!['imap', 'imaps', 'pop3', 'pop3s'].includes(protocol)) return null;
      return { port, protocol };
    })
    .filter(Boolean);
}

export function publicMailboxAccessListeners(listeners, { tls: tlsEnabled = false } = {}) {
  return listeners.map((listener) => ({
    port: listener.port,
    protocol: publicProtocolLabel(listener.protocol, tlsEnabled)
  }));
}

function startProtocolServers(kind, enabled, listeners = [], config, tlsMaterial) {
  if (!enabled) return [];
  const servers = [];
  for (const listener of listeners.filter((item) => item.protocol.startsWith(kind))) {
    const implicitTls = listener.protocol.endsWith('s');
    if (implicitTls && !tlsMaterial) {
      console.warn(`MailHub ${listener.protocol.toUpperCase()} listener on ${listener.port} skipped; TLS certificate is not configured.`);
      continue;
    }
    const listenerConfig = {
      ...config,
      port: listener.port,
      protocol: listener.protocol,
      secureContext: tlsMaterial?.secureContext || null,
      tlsActive: implicitTls,
      startTlsAvailable: !implicitTls && Boolean(tlsMaterial?.secureContext)
    };
    const handler = (socket) => (
      kind === 'imap'
        ? new ImapSession(socket, listenerConfig)
        : new Pop3Session(socket, listenerConfig)
    );
    const server = implicitTls
      ? tls.createServer({ key: tlsMaterial.key, cert: tlsMaterial.cert }, handler)
      : net.createServer(handler);
    server.listen(listener.port, '0.0.0.0', () => {
      console.log(`MailHub ${listener.protocol.toUpperCase()} listening on 0.0.0.0:${listener.port}`);
    });
    servers.push(server);
  }
  return servers;
}

class ImapSession {
  constructor(socket, config) {
    this.socket = socket;
    this.config = config;
    this.buffer = '';
    this.authenticated = false;
    this.user = null;
    this.mailbox = null;
    this.selectedFolder = 'INBOX';
    this.selected = false;
    this.messages = [];
    this.deletedUids = new Set();
    this.authContinuation = null;
    this.pendingAppend = null;
    this.idleTag = '';
    this.onDataBound = (chunk) => this.onData(chunk);
    socket.setEncoding('utf8');
    socket.on('data', this.onDataBound);
    socket.on('error', () => null);
    this.write(`* OK ${config.hostname} MailHub IMAP ready`);
  }

  onData(chunk) {
    this.buffer += chunk;
    while (true) {
      if (this.pendingAppend) {
        const literal = takeUtf8Literal(this.buffer, this.pendingAppend.bytes);
        if (!literal) return;
        this.buffer = literal.rest;
        if (this.buffer.startsWith('\r\n')) this.buffer = this.buffer.slice(2);
        else if (this.buffer.startsWith('\n')) this.buffer = this.buffer.slice(1);
        const pending = this.pendingAppend;
        this.pendingAppend = null;
        this.finishAppend(pending, literal.value);
        continue;
      }

      const index = this.buffer.indexOf('\n');
      if (index === -1) return;
      const line = this.buffer.slice(0, index).replace(/\r$/, '');
      this.buffer = this.buffer.slice(index + 1);
      this.onLine(line);
    }
  }

  onLine(line) {
    if (this.idleTag) {
      if (line.toUpperCase() === 'DONE') {
        const tag = this.idleTag;
        this.idleTag = '';
        this.write(`${tag} OK IDLE completed`);
      }
      return;
    }

    if (this.authContinuation) {
      const continuation = this.authContinuation;
      this.authContinuation = null;
      return this.finishAuthenticatePlain(continuation.tag, line);
    }

    const parsed = line.match(/^(\S+)\s+(\S+)(?:\s+(.*))?$/);
    if (!parsed) return this.write('* BAD Invalid command');
    const [, tag, rawCommand, rest = ''] = parsed;
    const command = rawCommand.toUpperCase();

    if (command === 'CAPABILITY') return this.capability(tag);
    if (command === 'NOOP') return this.write(`${tag} OK NOOP completed`);
    if (command === 'LOGOUT') {
      this.write('* BYE MailHub IMAP closing connection');
      this.write(`${tag} OK LOGOUT completed`);
      return this.socket.end();
    }
    if (command === 'STARTTLS') return this.startTls(tag);
    if (command === 'LOGIN') return this.login(tag, rest);
    if (command === 'AUTHENTICATE') return this.authenticate(tag, rest);
    if (!this.authenticated) return this.write(`${tag} NO Authentication required`);
    if (command === 'LIST' || command === 'LSUB') return this.list(tag);
    if (command === 'NAMESPACE') return this.namespace(tag);
    if (command === 'ID') return this.write(`${tag} OK ID completed`);
    if (command === 'SELECT' || command === 'EXAMINE') return this.select(tag, rest, command === 'EXAMINE');
    if (command === 'STATUS') return this.status(tag, rest);
    if (command === 'CREATE') return this.createFolder(tag, rest);
    if (command === 'APPEND') return this.append(tag, rest);
    if (command === 'SEARCH') return this.search(tag, rest, false);
    if (command === 'UID') return this.uid(tag, rest);
    if (!this.selected) return this.write(`${tag} NO Select a mailbox first`);
    if (command === 'FETCH') return this.fetch(tag, rest, false);
    if (command === 'STORE') return this.store(tag, rest, false);
    if (command === 'EXPUNGE') return this.expunge(tag);
    if (command === 'CLOSE') return this.closeMailbox(tag);
    if (command === 'IDLE') return this.idle(tag);
    return this.write(`${tag} BAD Command not implemented`);
  }

  capability(tag) {
    const capabilities = ['IMAP4rev1', 'UIDPLUS', 'IDLE', 'NAMESPACE', 'SPECIAL-USE'];
    if (this.config.startTlsAvailable && !this.config.tlsActive) capabilities.push('STARTTLS');
    if (this.canAuthenticate()) capabilities.push('AUTH=PLAIN');
    this.write(`* CAPABILITY ${capabilities.join(' ')}`);
    this.write(`${tag} OK CAPABILITY completed`);
  }

  startTls(tag) {
    if (!this.config.startTlsAvailable || !this.config.secureContext) return this.write(`${tag} NO TLS is not available`);
    this.write(`${tag} OK Begin TLS negotiation now`);
    this.upgradeToTls();
  }

  login(tag, rest) {
    if (!this.canAuthenticate()) return this.write(`${tag} NO Encryption required for authentication`);
    const [username, password] = tokenizeImap(rest);
    if (!username || password === undefined) return this.write(`${tag} BAD LOGIN expects username and password`);
    const auth = verifyInboundMailboxCredential(username, password);
    if (!auth) return this.write(`${tag} NO Authentication failed`);
    this.user = auth.user;
    this.mailbox = auth.mailbox;
    this.authenticated = true;
    this.write(`${tag} OK LOGIN completed`);
  }

  authenticate(tag, rest) {
    if (!this.canAuthenticate()) return this.write(`${tag} NO Encryption required for authentication`);
    const [method, initial] = tokenizeImap(rest);
    if (String(method || '').toUpperCase() !== 'PLAIN') return this.write(`${tag} NO Unsupported authentication method`);
    if (initial) return this.finishAuthenticatePlain(tag, initial);
    this.authContinuation = { tag };
    this.write('+');
  }

  finishAuthenticatePlain(tag, response) {
    const decoded = decodeBase64(response);
    const parts = decoded.split('\u0000');
    const username = parts[1] || parts[0] || '';
    const password = parts[2] || parts[1] || '';
    const auth = verifyInboundMailboxCredential(username, password);
    if (!auth) return this.write(`${tag} NO Authentication failed`);
    this.user = auth.user;
    this.mailbox = auth.mailbox;
    this.authenticated = true;
    this.write(`${tag} OK AUTHENTICATE completed`);
  }

  list(tag) {
    for (const folder of listInboundFolders(this.mailbox)) {
      this.write(`* LIST (${imapFolderAttributes(folder).join(' ')}) "/" ${imapNString(folder)}`);
    }
    this.write(`${tag} OK LIST completed`);
  }

  namespace(tag) {
    this.write('* NAMESPACE (("" "/")) NIL NIL');
    this.write(`${tag} OK NAMESPACE completed`);
  }

  select(tag, rest, readOnly) {
    const [mailboxName] = tokenizeImap(rest);
    const folder = normalizeImapFolder(mailboxName);
    if (!inboundFolderExists(this.mailbox, folder)) return this.write(`${tag} NO Mailbox does not exist`);
    this.selectedFolder = folder;
    this.reloadMessages();
    this.selected = true;
    this.write('* FLAGS (\\Seen \\Deleted)');
    this.write(`* ${this.messages.length} EXISTS`);
    this.write('* 0 RECENT');
    this.write(`* OK [UIDVALIDITY ${this.mailbox.id}] UIDs valid`);
    this.write(`* OK [UIDNEXT ${uidNext(this.messages)}] Predicted next UID`);
    this.write('* OK [PERMANENTFLAGS (\\Seen \\Deleted)] Limited flags permitted');
    this.write(`${tag} OK [${readOnly ? 'READ-ONLY' : 'READ-WRITE'}] SELECT completed`);
  }

  status(tag, rest) {
    const [mailboxName] = tokenizeImap(rest);
    const folder = normalizeImapFolder(mailboxName);
    if (!inboundFolderExists(this.mailbox, folder)) return this.write(`${tag} NO Mailbox does not exist`);
    const messages = mailboxProtocolMessages(this.mailbox, folder);
    const unseen = messages.filter((message) => !message.read).length;
    this.write(`* STATUS ${imapNString(folder)} (MESSAGES ${messages.length} UNSEEN ${unseen} UIDNEXT ${uidNext(messages)} UIDVALIDITY ${this.mailbox.id})`);
    this.write(`${tag} OK STATUS completed`);
  }

  createFolder(tag, rest) {
    const [mailboxName] = tokenizeImap(rest);
    const folder = normalizeImapFolder(mailboxName);
    if (!folder) return this.write(`${tag} BAD CREATE expects a mailbox name`);
    createInboundFolder(this.mailbox, folder);
    this.write(`${tag} OK CREATE completed`);
  }

  append(tag, rest) {
    const literalMatch = String(rest || '').match(/\{(\d+)\+?\}\s*$/);
    if (!literalMatch) return this.write(`${tag} BAD APPEND expects a literal message`);
    const bytes = Number(literalMatch[1]);
    if (!Number.isInteger(bytes) || bytes < 0) return this.write(`${tag} BAD APPEND literal size is invalid`);
    const prefix = rest.slice(0, literalMatch.index).trim();
    const [mailboxName] = tokenizeImap(prefix);
    const folder = normalizeImapFolder(mailboxName);
    if (!inboundFolderExists(this.mailbox, folder)) return this.write(`${tag} NO Mailbox does not exist`);
    this.pendingAppend = {
      tag,
      folder,
      flags: parseFlags(prefix),
      bytes
    };
    this.write('+ Ready for literal data');
  }

  finishAppend(pending, rawMessage) {
    const normalizedRaw = normalizeRawMessage({ rawMessage });
    const headers = parseMessageHeaders(normalizedRaw);
    const message = createInboundMessage(this.mailbox, {
      folder: pending.folder,
      sender: extractFirstEmail(headers.from) || headers.from || '',
      recipients: extractEmailAddresses(headers.to),
      subject: headers.subject || '(no subject)',
      messageId: headers['message-id'] || '',
      rawMessage: normalizedRaw,
      textBody: bodyBlock(normalizedRaw).trim()
    });
    if (pending.flags.has('\\SEEN')) markInboundMessageRead(this.mailbox.userId, message.id, true);
    this.write(`${pending.tag} OK APPEND completed`);
  }

  uid(tag, rest) {
    const parsed = rest.match(/^(\S+)(?:\s+(.*))?$/);
    if (!parsed) return this.write(`${tag} BAD UID expects a subcommand`);
    const subcommand = parsed[1].toUpperCase();
    const args = parsed[2] || '';
    if (subcommand === 'FETCH') return this.fetch(tag, args, true);
    if (subcommand === 'STORE') return this.store(tag, args, true);
    if (subcommand === 'SEARCH') return this.search(tag, args, true);
    return this.write(`${tag} BAD UID subcommand not implemented`);
  }

  search(tag, _rest, byUid) {
    if (!this.selected) this.reloadMessages();
    const values = this.messages.map((message, index) => byUid ? message.id : index + 1);
    this.write(`* SEARCH ${values.join(' ')}`.trimEnd());
    this.write(`${tag} OK SEARCH completed`);
  }

  fetch(tag, rest, byUid) {
    if (!this.selected) return this.write(`${tag} NO Select INBOX first`);
    const [set, items = ''] = splitFirst(rest);
    const entries = resolveMessageSet(set, this.messages, byUid);
    for (const entry of entries) this.sendFetch(entry, items, byUid);
    this.write(`${tag} OK FETCH completed`);
  }

  sendFetch(entry, items, byUid) {
    const upper = String(items || '').toUpperCase();
    const attrs = [];
    if (byUid || /\bUID\b/.test(upper)) attrs.push(`UID ${entry.message.id}`);
    if (!upper || /\bFLAGS\b/.test(upper)) attrs.push(`FLAGS (${imapFlags(entry.message, this.deletedUids).join(' ')})`);
    if (/\bINTERNALDATE\b/.test(upper)) attrs.push(`INTERNALDATE "${imapDate(entry.message.receivedAt)}"`);
    if (/RFC822\.SIZE|RFC822|BODY(?:\.PEEK)?\[/i.test(items)) attrs.push(`RFC822.SIZE ${messageBytes(entry.message)}`);
    if (/\bENVELOPE\b/.test(upper)) attrs.push(`ENVELOPE ${imapEnvelope(entry.message)}`);
    if (/\bBODYSTRUCTURE\b/.test(upper)) attrs.push(`BODYSTRUCTURE ${imapBodyStructure(entry.message)}`);

    const literal = resolveFetchLiteral(items, entry.message);
    if (!literal) {
      this.write(`* ${entry.seq} FETCH (${attrs.join(' ')})`);
      return;
    }
    const prefix = `* ${entry.seq} FETCH (${[...attrs, `${literal.label} {${Buffer.byteLength(literal.value, 'utf8')}}`].join(' ')}\r\n`;
    this.socket.write(prefix);
    this.socket.write(literal.value);
    this.socket.write('\r\n)\r\n');
  }

  store(tag, rest, byUid) {
    const parsed = rest.match(/^(\S+)\s+(\S+)\s+(.+)$/);
    if (!parsed) return this.write(`${tag} BAD STORE expects sequence, item, and flags`);
    const [, set, itemRaw, flagsRaw] = parsed;
    const item = itemRaw.toUpperCase();
    const silent = item.includes('.SILENT');
    const entries = resolveMessageSet(set, this.messages, byUid);
    const flags = parseFlags(flagsRaw);
    for (const entry of entries) {
      if (flags.has('\\SEEN')) {
        const read = !item.startsWith('-FLAGS');
        markInboundMessageRead(this.mailbox.userId, entry.message.id, read);
        entry.message.read = read;
      }
      if (flags.has('\\DELETED')) {
        if (item.startsWith('-FLAGS')) this.deletedUids.delete(entry.message.id);
        else this.deletedUids.add(entry.message.id);
      }
      if (!silent) this.write(`* ${entry.seq} FETCH (FLAGS (${imapFlags(entry.message, this.deletedUids).join(' ')}))`);
    }
    this.write(`${tag} OK STORE completed`);
  }

  expunge(tag) {
    const entries = this.messages
      .map((message, index) => ({ message, seq: index + 1 }))
      .filter((entry) => this.deletedUids.has(entry.message.id));
    softDeleteInboundMessages(this.mailbox.userId, this.mailbox.id, entries.map((entry) => entry.message.id), { folder: this.selectedFolder });
    for (const entry of entries.reverse()) this.write(`* ${entry.seq} EXPUNGE`);
    this.deletedUids.clear();
    this.reloadMessages();
    this.write(`${tag} OK EXPUNGE completed`);
  }

  closeMailbox(tag) {
    const ids = [...this.deletedUids];
    if (ids.length) softDeleteInboundMessages(this.mailbox.userId, this.mailbox.id, ids, { folder: this.selectedFolder });
    this.deletedUids.clear();
    this.selected = false;
    this.messages = [];
    this.write(`${tag} OK CLOSE completed`);
  }

  idle(tag) {
    this.idleTag = tag;
    this.write('+ idling');
  }

  reloadMessages() {
    this.messages = mailboxProtocolMessages(this.mailbox, this.selectedFolder);
  }

  upgradeToTls() {
    this.socket.removeListener('data', this.onDataBound);
    const secureSocket = new tls.TLSSocket(this.socket, {
      isServer: true,
      secureContext: this.config.secureContext
    });
    this.socket = secureSocket;
    this.buffer = '';
    this.config = { ...this.config, tlsActive: true, startTlsAvailable: false };
    secureSocket.setEncoding('utf8');
    secureSocket.on('data', this.onDataBound);
    secureSocket.on('error', () => null);
  }

  canAuthenticate() {
    return this.config.tlsActive || this.config.allowInsecureAuth;
  }

  write(line) {
    this.socket.write(`${line}\r\n`);
  }
}

class Pop3Session {
  constructor(socket, config) {
    this.socket = socket;
    this.config = config;
    this.buffer = '';
    this.username = '';
    this.authenticated = false;
    this.user = null;
    this.mailbox = null;
    this.messages = [];
    this.deletedIndexes = new Set();
    this.onDataBound = (chunk) => this.onData(chunk);
    socket.setEncoding('utf8');
    socket.on('data', this.onDataBound);
    socket.on('error', () => null);
    this.write(`+OK ${config.hostname} MailHub POP3 ready`);
  }

  onData(chunk) {
    this.buffer += chunk;
    let index;
    while ((index = this.buffer.indexOf('\n')) !== -1) {
      const line = this.buffer.slice(0, index).replace(/\r$/, '');
      this.buffer = this.buffer.slice(index + 1);
      this.onLine(line);
    }
  }

  onLine(line) {
    const [rawCommand, ...parts] = line.split(' ');
    const command = String(rawCommand || '').toUpperCase();
    const rest = parts.join(' ').trim();
    if (command === 'CAPA') return this.capa();
    if (command === 'QUIT') return this.quit();
    if (command === 'NOOP') return this.write('+OK');
    if (command === 'STLS') return this.startTls();
    if (command === 'USER') return this.userCommand(rest);
    if (command === 'PASS') return this.pass(rest);
    if (command === 'AUTH') return this.auth(rest);
    if (!this.authenticated) return this.write('-ERR Authentication required');
    if (command === 'STAT') return this.stat();
    if (command === 'LIST') return this.list(rest);
    if (command === 'UIDL') return this.uidl(rest);
    if (command === 'RETR') return this.retr(rest);
    if (command === 'TOP') return this.top(rest);
    if (command === 'DELE') return this.dele(rest);
    if (command === 'RSET') {
      this.deletedIndexes.clear();
      return this.write('+OK');
    }
    return this.write('-ERR Command not implemented');
  }

  capa() {
    this.write('+OK Capability list follows');
    this.write('USER');
    this.write('UIDL');
    this.write('TOP');
    if (this.config.startTlsAvailable && !this.config.tlsActive) this.write('STLS');
    this.write('.');
  }

  startTls() {
    if (!this.config.startTlsAvailable || !this.config.secureContext) return this.write('-ERR TLS is not available');
    this.write('+OK Begin TLS negotiation now');
    this.upgradeToTls();
  }

  userCommand(username) {
    if (!this.canAuthenticate()) return this.write('-ERR Encryption required for authentication');
    this.username = username;
    this.write('+OK User accepted');
  }

  pass(password) {
    if (!this.canAuthenticate()) return this.write('-ERR Encryption required for authentication');
    if (!this.username) return this.write('-ERR USER required before PASS');
    return this.finishAuth(this.username, password);
  }

  auth(rest) {
    const [method, response] = rest.split(/\s+/, 2);
    if (String(method || '').toUpperCase() !== 'PLAIN' || !response) return this.write('-ERR Unsupported authentication method');
    const parts = decodeBase64(response).split('\u0000');
    return this.finishAuth(parts[1] || parts[0] || '', parts[2] || parts[1] || '');
  }

  finishAuth(username, password) {
    const auth = verifyInboundMailboxCredential(username, password);
    if (!auth) return this.write('-ERR Authentication failed');
    this.user = auth.user;
    this.mailbox = auth.mailbox;
    this.authenticated = true;
    this.messages = mailboxProtocolMessages(this.mailbox);
    this.deletedIndexes.clear();
    return this.write('+OK Mailbox locked and ready');
  }

  stat() {
    const active = this.activeMessages();
    this.write(`+OK ${active.length} ${active.reduce((total, item) => total + messageBytes(item.message), 0)}`);
  }

  list(rest) {
    if (rest) {
      const entry = this.messageByNumber(rest);
      if (!entry) return this.write('-ERR No such message');
      return this.write(`+OK ${entry.index} ${messageBytes(entry.message)}`);
    }
    this.write('+OK Message list follows');
    for (const entry of this.activeMessages()) this.write(`${entry.index} ${messageBytes(entry.message)}`);
    this.write('.');
  }

  uidl(rest) {
    if (rest) {
      const entry = this.messageByNumber(rest);
      if (!entry) return this.write('-ERR No such message');
      return this.write(`+OK ${entry.index} ${pop3Uid(entry.message)}`);
    }
    this.write('+OK Unique IDs follow');
    for (const entry of this.activeMessages()) this.write(`${entry.index} ${pop3Uid(entry.message)}`);
    this.write('.');
  }

  retr(rest) {
    const entry = this.messageByNumber(rest);
    if (!entry) return this.write('-ERR No such message');
    const rawMessage = normalizeRawMessage(entry.message);
    this.write(`+OK ${Buffer.byteLength(rawMessage, 'utf8')} octets`);
    this.socket.write(`${dotStuff(rawMessage)}\r\n.\r\n`);
  }

  top(rest) {
    const [messageNumber, lineCountRaw] = rest.split(/\s+/, 2);
    const entry = this.messageByNumber(messageNumber);
    if (!entry) return this.write('-ERR No such message');
    const lineCount = Math.max(0, Number(lineCountRaw || 0) || 0);
    const preview = topLines(normalizeRawMessage(entry.message), lineCount);
    this.write('+OK Top of message follows');
    this.socket.write(`${dotStuff(preview)}\r\n.\r\n`);
  }

  dele(rest) {
    const entry = this.messageByNumber(rest);
    if (!entry) return this.write('-ERR No such message');
    this.deletedIndexes.add(entry.index);
    this.write(`+OK Message ${entry.index} deleted`);
  }

  quit() {
    if (this.authenticated && this.deletedIndexes.size) {
      const ids = [...this.deletedIndexes]
        .map((index) => this.messages[index - 1]?.id)
        .filter(Boolean);
      softDeleteInboundMessages(this.mailbox.userId, this.mailbox.id, ids);
    }
    this.write('+OK Bye');
    this.socket.end();
  }

  activeMessages() {
    return this.messages
      .map((message, index) => ({ message, index: index + 1 }))
      .filter((entry) => !this.deletedIndexes.has(entry.index));
  }

  messageByNumber(value) {
    const index = Number(value);
    if (!Number.isInteger(index) || index < 1 || index > this.messages.length || this.deletedIndexes.has(index)) return null;
    return { message: this.messages[index - 1], index };
  }

  upgradeToTls() {
    this.socket.removeListener('data', this.onDataBound);
    const secureSocket = new tls.TLSSocket(this.socket, {
      isServer: true,
      secureContext: this.config.secureContext
    });
    this.socket = secureSocket;
    this.buffer = '';
    this.config = { ...this.config, tlsActive: true, startTlsAvailable: false };
    secureSocket.setEncoding('utf8');
    secureSocket.on('data', this.onDataBound);
    secureSocket.on('error', () => null);
  }

  canAuthenticate() {
    return this.config.tlsActive || this.config.allowInsecureAuth;
  }

  write(line) {
    this.socket.write(`${line}\r\n`);
  }
}

function loadTlsMaterial(config) {
  if (!config.tlsKeyPath || !config.tlsCertPath) return null;
  try {
    const key = readFileSync(config.tlsKeyPath);
    const cert = readFileSync(config.tlsCertPath);
    return {
      key,
      cert,
      secureContext: tls.createSecureContext({ key, cert })
    };
  } catch (error) {
    console.warn(`Unable to load mailbox access TLS certificate: ${error.message}`);
    return null;
  }
}

function publicProtocolLabel(protocol, tlsEnabled) {
  if (protocol === 'imaps') return 'IMAPS';
  if (protocol === 'pop3s') return 'POP3S';
  if (protocol === 'imap') return tlsEnabled ? 'IMAP + STARTTLS' : 'IMAP';
  return tlsEnabled ? 'POP3 + STLS' : 'POP3';
}

function mailboxProtocolMessages(mailbox, folder = 'INBOX') {
  return listInboundMailboxProtocolMessages(mailbox, { folder }).map((message) => ({
    ...message,
    rawMessage: normalizeRawMessage(message)
  }));
}

function tokenizeImap(value) {
  const tokens = [];
  const input = String(value || '');
  let token = '';
  let quoted = false;
  let escaping = false;
  for (const char of input) {
    if (escaping) {
      token += char;
      escaping = false;
      continue;
    }
    if (quoted && char === '\\') {
      escaping = true;
      continue;
    }
    if (char === '"') {
      quoted = !quoted;
      continue;
    }
    if (!quoted && /\s/.test(char)) {
      if (token) {
        tokens.push(token);
        token = '';
      }
      continue;
    }
    token += char;
  }
  if (token) tokens.push(token);
  return tokens;
}

function takeUtf8Literal(input, byteCount) {
  let bytes = 0;
  let end = 0;
  for (const char of String(input || '')) {
    bytes += Buffer.byteLength(char, 'utf8');
    end += char.length;
    if (bytes === byteCount) return { value: input.slice(0, end), rest: input.slice(end) };
    if (bytes > byteCount) return null;
  }
  return byteCount === 0 ? { value: '', rest: input } : null;
}

function parseMessageHeaders(rawMessage) {
  const headers = {};
  let current = '';
  for (const line of headerBlock(rawMessage).replace(/\r\n\r\n$/, '').split('\r\n')) {
    if (!line) continue;
    if (/^[\t ]/.test(line) && current) {
      headers[current] = `${headers[current]} ${line.trim()}`.trim();
      continue;
    }
    const separator = line.indexOf(':');
    if (separator === -1) continue;
    current = line.slice(0, separator).trim().toLowerCase();
    headers[current] = line.slice(separator + 1).trim();
  }
  return headers;
}

function extractEmailAddresses(value) {
  return String(value || '').match(/[^\s<>,;"]+@[^\s<>,;"]+/g) || [];
}

function extractFirstEmail(value) {
  return extractEmailAddresses(value)[0] || '';
}

function splitFirst(value) {
  const input = String(value || '').trim();
  const index = input.search(/\s/);
  if (index === -1) return [input, ''];
  return [input.slice(0, index), input.slice(index + 1).trim()];
}

function normalizeImapFolder(value) {
  const raw = String(value || '').trim().replace(/^"|"$/g, '').replace(/\\/g, '/');
  if (!raw || /[\r\n\u0000]/.test(raw)) return '';
  if (raw.toUpperCase() === 'INBOX') return 'INBOX';
  const standard = STANDARD_INBOUND_FOLDERS.find((folder) => folder.toLowerCase() === raw.toLowerCase());
  if (standard) return standard;
  return raw
    .split('/')
    .map((part) => part.trim())
    .filter(Boolean)
    .join('/');
}

function imapFolderAttributes(folder) {
  const attrs = ['\\HasNoChildren'];
  const specialUse = {
    Sent: '\\Sent',
    Drafts: '\\Drafts',
    Trash: '\\Trash',
    Junk: '\\Junk',
    Archive: '\\Archive'
  }[folder];
  if (specialUse) attrs.push(specialUse);
  return attrs;
}

function resolveMessageSet(set, messages, byUid) {
  const max = messages.length;
  const entries = [];
  for (const part of String(set || '').split(',').filter(Boolean)) {
    const [startRaw, endRaw] = part.split(':');
    const start = resolveSetValue(startRaw, messages, byUid);
    const end = endRaw === undefined ? start : resolveSetValue(endRaw, messages, byUid);
    if (start === null || end === null) continue;
    const low = Math.min(start, end);
    const high = Math.max(start, end);
    for (let index = 0; index < max; index += 1) {
      const value = byUid ? messages[index].id : index + 1;
      if (value >= low && value <= high) entries.push({ seq: index + 1, message: messages[index] });
    }
  }
  return [...new Map(entries.map((entry) => [entry.message.id, entry])).values()];
}

function resolveSetValue(value, messages, byUid) {
  const clean = String(value || '').trim();
  if (clean === '*') return byUid ? messages.at(-1)?.id || 0 : messages.length;
  const number = Number(clean);
  return Number.isInteger(number) && number >= 0 ? number : null;
}

function resolveFetchLiteral(items, message) {
  const raw = normalizeRawMessage(message);
  if (/\bRFC822\b(?!\.SIZE|\.HEADER|\.TEXT)/i.test(items)) return { label: 'RFC822', value: raw };
  if (/RFC822\.HEADER/i.test(items)) return { label: 'RFC822.HEADER', value: headerBlock(raw) };
  if (/RFC822\.TEXT/i.test(items)) return { label: 'RFC822.TEXT', value: bodyBlock(raw) };
  const bodyMatch = String(items || '').match(/BODY(?:\.PEEK)?\[([^\]]*)\]/i);
  if (!bodyMatch) return null;
  const section = bodyMatch[1] || '';
  return {
    label: `BODY[${section}]`,
    value: bodySection(raw, section)
  };
}

function bodySection(raw, section) {
  const clean = String(section || '').trim().toUpperCase();
  if (!clean) return raw;
  if (clean === 'HEADER') return headerBlock(raw);
  if (clean === 'TEXT') return bodyBlock(raw);
  if (clean.startsWith('HEADER.FIELDS')) return selectedHeaders(raw, clean);
  const match = clean.match(/^(\d+(?:\.\d+)*)(?:\.(MIME|HEADER|TEXT))?$/);
  if (match) {
    const node = resolveMimeSection(parseMimeNode(raw), match[1]);
    if (!node) return '';
    if (match[2] === 'MIME' || match[2] === 'HEADER') return headerBlock(node.raw);
    return node.body;
  }
  return raw;
}

function imapBodyStructure(message) {
  return imapMimeNodeStructure(parseMimeNode(normalizeRawMessage(message)));
}

function imapMimeNodeStructure(node) {
  if (node.children.length) {
    return `(${node.children.map(imapMimeNodeStructure).join(' ')} ${imapNString(node.contentType.subtype.toUpperCase())} ${imapBodyParameters(node.contentType.parameters)})`;
  }

  const values = [
    imapNString(node.contentType.primary.toUpperCase()),
    imapNString(node.contentType.subtype.toUpperCase()),
    imapBodyParameters(node.contentType.parameters),
    imapNString(node.headers['content-id'] || ''),
    imapNString(node.headers['content-description'] || ''),
    imapNString(node.encoding.toUpperCase()),
    String(Buffer.byteLength(node.body, 'utf8'))
  ];
  if (node.contentType.primary === 'text') values.push(String(imapLineCount(node.body)));
  return `(${values.join(' ')})`;
}

function imapBodyParameters(parameters) {
  const entries = Object.entries(parameters);
  if (!entries.length) return 'NIL';
  return `(${entries.map(([name, value]) => `${imapNString(name.toUpperCase())} ${imapNString(value)}`).join(' ')})`;
}

function imapLineCount(value) {
  const body = String(value || '').replace(/\r\n$/, '');
  return body ? body.split('\r\n').length : 0;
}

function parseMimeNode(rawMessage) {
  const raw = String(rawMessage || '').replace(/\r?\n/g, '\r\n');
  const headers = parseMessageHeaders(raw);
  const contentType = parseMimeContentType(headers['content-type']);
  const body = bodyBlock(raw);
  const boundary = contentType.primary === 'multipart' ? contentType.parameters.boundary : '';
  return {
    raw,
    headers,
    body,
    contentType,
    encoding: normalizeTransferEncoding(headers['content-transfer-encoding']),
    children: boundary ? splitMultipartParts(body, boundary).map(parseMimeNode) : []
  };
}

function parseMimeContentType(value) {
  const source = String(value || 'text/plain');
  const mediaType = source.split(';', 1)[0].trim().toLowerCase();
  const [primary = 'text', subtype = 'plain'] = mediaType.split('/');
  return {
    primary: normalizeMimeToken(primary, 'text'),
    subtype: normalizeMimeToken(subtype, 'plain'),
    parameters: parseMimeParameters(source)
  };
}

function parseMimeParameters(value) {
  const parameters = {};
  const expression = /;\s*([^=;\s]+)\s*=\s*(?:"((?:\\.|[^"])*)"|([^;]*))/g;
  for (const match of String(value || '').matchAll(expression)) {
    const name = String(match[1] || '').trim().toLowerCase();
    const parameterValue = String(match[2] ?? match[3] ?? '').trim().replace(/\\(.)/g, '$1');
    if (name) parameters[name] = parameterValue;
  }
  return parameters;
}

function normalizeMimeToken(value, fallback) {
  const token = String(value || '').trim().replace(/[^a-z0-9!#$&^_.+-]/gi, '');
  return token || fallback;
}

function normalizeTransferEncoding(value) {
  const encoding = String(value || '7bit').trim().toLowerCase();
  return normalizeMimeToken(encoding, '7bit');
}

function splitMultipartParts(body, boundary) {
  const marker = `--${boundary}`;
  const parts = [];
  let current = null;
  for (const line of String(body || '').split('\r\n')) {
    if (line === marker || line === `${marker}--`) {
      if (current !== null) parts.push(current.join('\r\n'));
      if (line === `${marker}--`) break;
      current = [];
      continue;
    }
    if (current) current.push(line);
  }
  return parts.filter((part) => part.trim());
}

function resolveMimeSection(root, section) {
  const indexes = String(section || '').split('.').map(Number);
  if (!indexes.every((index) => Number.isInteger(index) && index > 0)) return null;
  if (!root.children.length) return indexes.length === 1 && indexes[0] === 1 ? root : null;
  let node = root;
  for (const index of indexes) {
    node = node.children[index - 1];
    if (!node) return null;
  }
  return node;
}

function selectedHeaders(raw, section) {
  const names = new Set((section.match(/\(([^)]*)\)/)?.[1] || '')
    .split(/\s+/)
    .map((name) => name.toLowerCase())
    .filter(Boolean));
  if (!names.size) return headerBlock(raw);
  const output = [];
  let keep = false;
  for (const line of headerBlock(raw).split('\r\n')) {
    if (!line) continue;
    if (/^[\t ]/.test(line)) {
      if (keep) output.push(line);
      continue;
    }
    const name = line.slice(0, line.indexOf(':')).toLowerCase();
    keep = names.has(name);
    if (keep) output.push(line);
  }
  return `${output.join('\r\n')}\r\n\r\n`;
}

function headerBlock(raw) {
  return `${raw.split('\r\n\r\n', 1)[0] || ''}\r\n\r\n`;
}

function bodyBlock(raw) {
  const index = raw.indexOf('\r\n\r\n');
  return index === -1 ? '' : raw.slice(index + 4);
}

function parseFlags(value) {
  return new Set(String(value || '').toUpperCase().match(/\\[A-Z]+/g) || []);
}

function imapFlags(message, deletedUids) {
  return [
    message.read ? '\\Seen' : '',
    deletedUids.has(message.id) ? '\\Deleted' : ''
  ].filter(Boolean);
}

function imapEnvelope(message) {
  return `("${imapDate(message.receivedAt)}" ${imapNString(message.subject)} ${addressList(message.sender)} NIL NIL ${addressList(message.sender)} ${addressList(message.sender)} NIL NIL ${imapNString(message.messageId)})`;
}

function addressList(address) {
  const clean = String(address || '');
  const [localPart, domain] = clean.split('@');
  if (!localPart || !domain) return 'NIL';
  return `((NIL NIL ${imapNString(localPart)} ${imapNString(domain)}))`;
}

function imapNString(value) {
  if (!value) return 'NIL';
  return `"${String(value).replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;
}

function imapDate(value) {
  const date = value ? new Date(value) : new Date();
  return date.toUTCString().replace(',', '');
}

function uidNext(messages) {
  return Math.max(0, ...messages.map((message) => Number(message.id) || 0)) + 1;
}

function messageBytes(message) {
  return Buffer.byteLength(normalizeRawMessage(message), 'utf8');
}

function normalizeRawMessage(message) {
  const raw = String(message.rawMessage || fallbackRawMessage(message) || '').replace(/\r?\n/g, '\r\n');
  return raw.endsWith('\r\n') ? raw : `${raw}\r\n`;
}

function fallbackRawMessage(message) {
  return [
    message.sender ? `From: ${message.sender}` : '',
    message.recipients?.length ? `To: ${message.recipients.join(', ')}` : '',
    message.subject ? `Subject: ${message.subject}` : '',
    message.messageId ? `Message-ID: ${message.messageId}` : '',
    message.receivedAt ? `Date: ${new Date(message.receivedAt).toUTCString()}` : '',
    '',
    message.textBody || message.preview || ''
  ].filter((line, index) => line || index >= 5).join('\r\n');
}

function dotStuff(rawMessage) {
  return String(rawMessage || '')
    .replace(/\r?\n/g, '\r\n')
    .split('\r\n')
    .map((line) => line.startsWith('.') ? `.${line}` : line)
    .join('\r\n')
    .replace(/\r\n$/, '');
}

function topLines(rawMessage, lineCount) {
  const header = headerBlock(rawMessage).replace(/\r\n\r\n$/, '');
  const lines = bodyBlock(rawMessage).split('\r\n').slice(0, lineCount).join('\r\n');
  return `${header}\r\n\r\n${lines}`;
}

function pop3Uid(message) {
  return `mh-${message.id}`;
}

function decodeBase64(value) {
  try {
    return Buffer.from(String(value || ''), 'base64').toString('utf8');
  } catch {
    return '';
  }
}
