import { App as AntApp, ConfigProvider, Form, Input, Modal, Select } from 'antd';
import { useEffect, useMemo, useState } from 'react';

import { AddDomainDrawer } from '../components/domain/AddDomainDrawer';
import { AdminLayout } from '../layouts/AdminLayout';
import AdminPage from '../pages/Admin';
import ApiTokens from '../pages/ApiTokens';
import Dashboard from '../pages/Dashboard';
import DnsApi from '../pages/DnsApi';
import DomainDetail from '../pages/Domains/DomainDetail';
import DomainsPage from '../pages/Domains';
import Inbox from '../pages/Inbox';
import PlaceholderPage from '../pages/PlaceholderPage';
import SendingLogs from '../pages/SendingLogs';
import Settings from '../pages/Settings';
import SmtpCredentials from '../pages/SmtpCredentials';
import Webhooks from '../pages/Webhooks';
import { I18nProvider, useI18n } from './i18n/react';
import { buildDnsApplyFeedback } from './domain-model.js';
import { api } from './services/api';
import './styles.css';
import { mailhubTheme } from './theme';
import type {
  AddDomainPayload,
  ApiToken,
  AppData,
  DnsCredential,
  Domain,
  DomainMode,
  DomainPatchPayload,
  InboundMailbox,
  InboundMessage,
  MailboxClientConfig,
  RuntimeConfig,
  SmtpCredential,
  SmtpRelay,
  SmtpRelayPayload,
  User,
  ViewKey
} from './types';

const emptyData: AppData = {
  me: null,
  config: null,
  domains: [],
  events: [],
  analytics: null,
  smtpCredential: null,
  smtpCredentials: [],
  smtpRelays: [],
  inboundMailboxes: [],
  inboundMessages: [],
  dnsCredentials: [],
  apiTokens: [],
  settings: null,
  users: []
};

const viewTitleKeys: Record<ViewKey, string> = {
  dashboard: 'nav.dashboard',
  domains: 'nav.domains',
  'dns-api': 'nav.dnsApi',
  smtp: 'nav.smtp',
  inbox: 'nav.inbox',
  tokens: 'nav.tokens',
  logs: 'nav.logs',
  webhooks: 'nav.webhooks',
  admin: 'nav.admin',
  settings: 'nav.settings'
};

export default function App() {
  return (
    <ConfigProvider theme={mailhubTheme}>
      <AntApp>
        <I18nProvider>
          <MailHubConsole />
        </I18nProvider>
      </AntApp>
    </ConfigProvider>
  );
}

function MailHubConsole() {
  const { message } = AntApp.useApp();
  const { t } = useI18n();
  const [data, setData] = useState<AppData>(emptyData);
  const [activeView, setActiveView] = useState<ViewKey>('dashboard');
  const [domainMode, setDomainMode] = useState<DomainMode>('list');
  const [selectedDomainId, setSelectedDomainId] = useState<number | null>(null);
  const [initialDomainTab, setInitialDomainTab] = useState('overview');
  const [addOpen, setAddOpen] = useState(false);
  const [loading, setLoading] = useState(true);
  const [actionLoading, setActionLoading] = useState(false);
  const [testDomain, setTestDomain] = useState<Domain | null>(null);
  const [testForm] = Form.useForm();

  const selectedDomain = data.domains.find((domain) => domain.id === selectedDomainId) || data.domains[0] || null;

  useEffect(() => {
    void loadAll();
  }, []);

  async function loadAll() {
    setLoading(true);
    try {
      const me = await api.me();
      const [
        config,
        domains,
        events,
        inboundMailboxes,
        inboundMessages,
        analytics,
        smtpCredential,
        smtpCredentials,
        smtpRelays,
        dnsCredentials,
        apiTokens
      ] = await Promise.all([
        api.config(),
        api.domains(),
        api.events(),
        api.inboundMailboxes(),
        api.inboundMessages(),
        api.analytics(7),
        api.smtpCredential(),
        api.smtpCredentials(),
        api.smtpRelays(),
        api.dnsCredentials(),
        api.apiTokens()
      ]);
      let settings: RuntimeConfig | null = null;
      let users: User[] = [];
      if (me.user.role === 'admin') {
        const [settingsResult, usersResult] = await Promise.all([api.adminSettings(), api.adminUsers()]);
        settings = settingsResult.settings;
        users = usersResult.users;
      }
      setData({
        me: me.user,
        config,
        domains: domains.domains || [],
        events: events.events || [],
        inboundMailboxes: inboundMailboxes.mailboxes || [],
        inboundMessages: inboundMessages.messages || [],
        analytics: analytics.analytics || null,
        smtpCredential: smtpCredential.credential || null,
        smtpCredentials: smtpCredentials.credentials || [],
        smtpRelays: smtpRelays.relays || [],
        dnsCredentials: dnsCredentials.credentials || [],
        apiTokens: apiTokens.tokens || [],
        settings,
        users
      });
      setSelectedDomainId((current) => {
        if (current && domains.domains.some((domain) => domain.id === current)) return current;
        return domains.domains[0]?.id || null;
      });
    } catch (error) {
      const text = error instanceof Error ? error.message : t('common.error');
      message.error(text);
      if (/Authentication required/i.test(text)) window.location.href = '/login';
    } finally {
      setLoading(false);
    }
  }

  function replaceDomain(domain: Domain) {
    setData((current) => ({
      ...current,
      domains: current.domains.map((item) => item.id === domain.id ? domain : item)
    }));
  }

  async function runAction<T>(fn: () => Promise<T>, success?: string) {
    setActionLoading(true);
    try {
      const result = await fn();
      if (success) message.success(success);
      return result;
    } catch (error) {
      message.error(error instanceof Error ? error.message : t('common.error'));
      return null;
    } finally {
      setActionLoading(false);
    }
  }

  async function createDomain(values: AddDomainPayload) {
    const immediateCheck = Boolean(values.immediateCheck);
    const result = await runAction(async () => api.createDomain(values), t('actions.domainCreated'));
    if (!result?.domain) return;
    let nextDomain = result.domain;
    setData((current) => ({ ...current, domains: [nextDomain, ...current.domains] }));
    setSelectedDomainId(nextDomain.id);
    setActiveView('domains');
    setDomainMode('detail');
    setInitialDomainTab('dns');
    setAddOpen(false);
    if (immediateCheck) {
      const checked = await runAction(async () => api.checkDomain(nextDomain.id), t('actions.dnsCheckCompleted'));
      if (checked?.domain) {
        nextDomain = checked.domain;
        replaceDomain(nextDomain);
      }
    }
  }

  function viewDetail(domain: Domain, tab = 'overview') {
    setSelectedDomainId(domain.id);
    setInitialDomainTab(tab);
    setDomainMode('detail');
    setActiveView('domains');
  }

  async function checkDomain(domain: Domain) {
    const result = await runAction(async () => api.checkDomain(domain.id), t('actions.dnsCheckRefreshed'));
    if (result?.domain) replaceDomain(result.domain);
  }

  async function applyDns(domain: Domain) {
    const result = await runAction(async () => api.applyDns(domain.id));
    if (result) {
      const feedback = buildDnsApplyFeedback(result.apply, {
        completed: t('actions.dnsApplyCompleted'),
        partial: t('actions.dnsApplyPartial')
      });
      if (feedback.type === 'warning') {
        message.warning(feedback.message);
      } else {
        message.success(feedback.message);
      }
    }
    if (result?.domain) {
      replaceDomain(result.domain);
      setInitialDomainTab('dns');
      viewDetail(result.domain, 'dns');
    }
  }

  async function patchDomain(domain: Domain, values: DomainPatchPayload) {
    const result = await runAction(async () => api.patchDomain(domain.id, values), t('actions.domainSaved'));
    if (result?.domain) replaceDomain(result.domain);
  }

  async function deleteDomain(domain: Domain) {
    const result = await runAction(async () => api.deleteDomain(domain.id), t('actions.domainDeleted'));
    if (!result?.deleted) return;
    setData((current) => ({ ...current, domains: current.domains.filter((item) => item.id !== domain.id) }));
    if (selectedDomainId === domain.id) {
      setSelectedDomainId(null);
      setDomainMode('list');
    }
  }

  function openTestModal(domain: Domain) {
    setTestDomain(domain);
    testForm.setFieldsValue({
      from: `noreply@${domain.domain}`,
      subject: `MailHub test for ${domain.domain}`,
      text: `This is a MailHub test message from ${domain.domain}.`,
      html: `<p>This is a MailHub test message from ${domain.domain}.</p><p><a href="${window.location.origin}/login">Open MailHub</a></p>`,
      smtpRelayId: domain.smtpRelayId || undefined
    });
  }

  async function submitTestMail() {
    if (!testDomain) return;
    const values = await testForm.validateFields();
    await runAction(async () => api.sendTest(testDomain.id, values), t('actions.testMailQueued'));
    setTestDomain(null);
    const [events, analytics] = await Promise.all([api.events(), api.analytics(7)]);
    setData((current) => ({ ...current, events: events.events || [], analytics: analytics.analytics || current.analytics }));
  }

  async function loadSendEvent(id: number) {
    const result = await api.event(id);
    return result.event;
  }

  async function copy(value: string) {
    if (!value || value === '-') return;
    await navigator.clipboard.writeText(value);
    message.success(t('common.copied'));
  }

  async function saveDnsCredential(values: Record<string, unknown>, id?: number) {
    const result = await runAction(async () => api.saveDnsCredential(values, id), id ? t('actions.dnsApiUpdated') : t('actions.dnsApiCreated'));
    if (!result?.credential) return;
    setData((current) => ({
      ...current,
      dnsCredentials: id
        ? current.dnsCredentials.map((item) => item.id === id ? result.credential : item)
        : [result.credential, ...current.dnsCredentials]
    }));
  }

  async function testDnsCredential(credential: DnsCredential) {
    await runAction(async () => api.testDnsCredential(credential.id), `${credential.name} ${t('actions.dnsApiTestCompleted')}`);
  }

  async function deleteDnsCredential(credential: DnsCredential) {
    const result = await runAction(async () => api.deleteDnsCredential(credential.id), t('actions.dnsApiDeleted'));
    if (!result?.deleted) return;
    setData((current) => ({
      ...current,
      dnsCredentials: current.dnsCredentials.filter((item) => item.id !== credential.id),
      domains: current.domains.map((domain) => domain.dnsCredentialId === credential.id ? { ...domain, dnsCredentialId: null } : domain)
    }));
  }

  async function loadSmtpLoginCredential(id: number) {
    const result = await runAction(async () => api.smtpCredentialDetail(id));
    return result?.credential || null;
  }

  async function saveSmtpLoginCredential(values: { username: string; password?: string }, id?: number) {
    const result = await runAction(
      async () => api.saveSmtpLoginCredential(values, id),
      id ? t('actions.smtpUpdated') : t('actions.smtpCreated')
    );
    if (!result?.credential) return null;
    setData((current) => {
      const credentials = id
        ? current.smtpCredentials.map((item) => item.id === id ? result.credential : item)
        : [result.credential, ...current.smtpCredentials];
      return {
        ...current,
        smtpCredential: credentials[0] || null,
        smtpCredentials: credentials,
        config: current.config?.submission
          ? {
              ...current.config,
              submission: {
                ...current.config.submission,
                username: credentials[0]?.username || '',
                passwordSet: Boolean(credentials[0]?.passwordSet)
              }
            }
          : current.config
      };
    });
    return result.credential;
  }

  async function deleteSmtpLoginCredential(credential: SmtpCredential) {
    const credentialId = credential.id;
    if (!credentialId) return;
    const result = await runAction(async () => api.deleteSmtpCredential(credentialId), t('actions.smtpDeleted'));
    if (!result?.deleted) return;
    setData((current) => {
      const credentials = current.smtpCredentials.filter((item) => item.id !== credentialId);
      return {
        ...current,
        smtpCredential: credentials[0] || null,
        smtpCredentials: credentials,
        config: current.config?.submission
          ? {
              ...current.config,
              submission: {
                ...current.config.submission,
                username: credentials[0]?.username || '',
                passwordSet: Boolean(credentials[0]?.passwordSet)
              }
            }
          : current.config
      };
    });
  }

  async function loadSmtpRelay(id: number) {
    const result = await runAction(async () => api.smtpRelay(id));
    return result?.relay || null;
  }

  async function saveSmtpRelay(values: SmtpRelayPayload, id?: number) {
    const result = await runAction(
      async () => api.saveSmtpRelay(values, id),
      id ? t('actions.smtpRelayUpdated') : t('actions.smtpRelayCreated')
    );
    if (!result?.relay) return null;
    setData((current) => ({
      ...current,
      smtpRelays: id
        ? current.smtpRelays.map((item) => item.id === id ? result.relay : item)
        : [result.relay, ...current.smtpRelays]
    }));
    return result.relay;
  }

  async function deleteSmtpRelay(relay: SmtpRelay) {
    const result = await runAction(async () => api.deleteSmtpRelay(relay.id), t('actions.smtpRelayDeleted'));
    if (!result?.deleted) return;
    setData((current) => ({
      ...current,
      smtpRelays: current.smtpRelays.filter((item) => item.id !== relay.id),
      domains: current.domains.map((domain) => domain.smtpRelayId === relay.id ? { ...domain, smtpRelayId: null } : domain)
    }));
  }

  async function createInboundMailbox(values: {
    address: string;
    displayName?: string;
    password: string;
    aliases?: string;
    forwardTo?: string;
    keepForwarded?: boolean;
    quotaMb?: number | string | null;
  }): Promise<{ mailbox: InboundMailbox; clientConfig?: MailboxClientConfig } | null> {
    const result = await runAction(async () => api.createInboundMailbox(values), t('actions.inboundMailboxCreated'));
    if (!result?.mailbox) return null;
    setData((current) => ({
      ...current,
      inboundMailboxes: [result.mailbox, ...current.inboundMailboxes]
    }));
    return result;
  }

  async function loadInboundMessages(mailboxId?: number | null) {
    const result = await runAction(async () => api.inboundMessages(mailboxId));
    if (!result?.messages) return [];
    setData((current) => ({ ...current, inboundMessages: result.messages }));
    return result.messages;
  }

  async function loadInboundMessage(id: number): Promise<InboundMessage | null> {
    const result = await api.inboundMessage(id);
    let inboundMessage = result.message;
    if (inboundMessage && !inboundMessage.read) {
      const readResult = await api.markInboundMessageRead(id, true);
      inboundMessage = readResult.message || { ...inboundMessage, read: true };
    }
    if (inboundMessage) {
      setData((current) => {
        const previous = current.inboundMessages.find((item) => item.id === inboundMessage.id);
        const shouldDecrementUnread = Boolean(previous && !previous.read && inboundMessage.read);
        return {
          ...current,
          inboundMessages: current.inboundMessages.map((item) => (
            item.id === inboundMessage.id ? { ...item, ...inboundMessage } : item
          )),
          inboundMailboxes: current.inboundMailboxes.map((mailbox) => (
            mailbox.id === inboundMessage.mailboxId && shouldDecrementUnread
              ? { ...mailbox, unreadCount: Math.max(0, mailbox.unreadCount - 1) }
              : mailbox
          ))
        };
      });
    }
    return inboundMessage;
  }

  async function createApiToken(values: { name: string; scopes: string[]; expiresAt?: string | null }) {
    const result = await runAction(async () => api.createApiToken(values), t('tokens.createdSuccess'));
    if (!result?.token) return null;
    setData((current) => ({ ...current, apiTokens: [result.token, ...current.apiTokens] }));
    return result.token;
  }

  async function updateApiToken(token: ApiToken, values: { name: string; scopes: string[]; expiresAt?: string | null }) {
    const result = await runAction(async () => api.updateApiToken(token.id, values), t('tokens.updatedSuccess'));
    if (!result?.token) return;
    setData((current) => ({
      ...current,
      apiTokens: current.apiTokens.map((item) => item.id === result.token.id ? result.token : item)
    }));
  }

  async function revokeApiToken(token: ApiToken) {
    const result = await runAction(async () => api.deleteApiToken(token.id), t('tokens.revokedSuccess'));
    if (!result?.token) return;
    setData((current) => ({
      ...current,
      apiTokens: current.apiTokens.map((item) => item.id === result.token?.id ? result.token : item)
    }));
  }

  async function saveSettings(values: Partial<RuntimeConfig>) {
    const result = await runAction(async () => api.saveAdminSettings(values), t('actions.settingsSaved'));
    if (!result?.settings) return;
    setData((current) => ({ ...current, settings: result.settings, config: { ...current.config, ...result.settings } as RuntimeConfig }));
  }

  async function logout() {
    await api.logout().catch(() => null);
    window.location.href = '/login';
  }

  const breadcrumb = useMemo(() => {
    if (activeView === 'domains' && domainMode === 'detail' && selectedDomain) return [t('nav.domains'), selectedDomain.domain];
    return [t(viewTitleKeys[activeView])];
  }, [activeView, domainMode, selectedDomain, t]);

  const runtimeLine = data.config
    ? `${data.config.mailHostname} · ${data.config.sendingIp || t('common.unsetSendingIp')}`
    : t('common.loadingConfig');

  const content = renderContent();

  return (
    <>
      <AdminLayout
        activeView={activeView}
        breadcrumb={breadcrumb}
        user={data.me}
        runtimeLine={runtimeLine}
        loading={loading}
        onViewChange={(view) => {
          setActiveView(view);
          if (view === 'domains') setDomainMode('list');
        }}
        onRefresh={loadAll}
        onAddDomain={() => setAddOpen(true)}
        onLogout={logout}
      >
        {content}
      </AdminLayout>
      <AddDomainDrawer
        open={addOpen}
        loading={actionLoading}
        config={data.config}
        dnsCredentials={data.dnsCredentials}
        smtpRelays={data.smtpRelays}
        onClose={() => setAddOpen(false)}
        onSubmit={createDomain}
      />
      <Modal
        title={testDomain ? `${t('testMail.title')} · ${testDomain.domain}` : t('testMail.title')}
        open={Boolean(testDomain)}
        confirmLoading={actionLoading}
        onCancel={() => setTestDomain(null)}
        onOk={submitTestMail}
      >
        <Form form={testForm} layout="vertical">
          <Form.Item name="from" label="From" rules={[{ required: true, message: t('testMail.fromRequired') }]}>
            <Input />
          </Form.Item>
          <Form.Item name="to" label="To" rules={[{ required: true, message: t('testMail.toRequired') }]}>
            <Input placeholder="user@example.com" />
          </Form.Item>
          <Form.Item name="subject" label="Subject">
            <Input />
          </Form.Item>
          <Form.Item name="text" label="Text">
            <Input.TextArea rows={5} />
          </Form.Item>
          <Form.Item name="html" label="HTML">
            <Input.TextArea rows={5} />
          </Form.Item>
          <Form.Item name="smtpRelayId" label={t('smtpRelay.domainDefault')}>
            <Select
              allowClear
              placeholder={t('smtpRelay.useResolutionOrder')}
              options={data.smtpRelays.map((relay) => ({
                value: relay.id,
                label: relayLabel(relay, t)
              }))}
            />
          </Form.Item>
        </Form>
      </Modal>
    </>
  );

  function renderContent() {
    if (activeView === 'dashboard') {
      return (
        <Dashboard
          analytics={data.analytics}
          domains={data.domains}
          events={data.events}
          config={data.config}
          smtpCredential={data.smtpCredential}
        />
      );
    }
    if (activeView === 'domains') {
      if (domainMode === 'detail' && selectedDomain) {
        return (
          <DomainDetail
            key={selectedDomain.id}
            domain={selectedDomain}
            config={data.config}
            smtpCredential={data.smtpCredential}
            apiTokens={data.apiTokens}
            events={data.events}
            dnsCredentials={data.dnsCredentials}
            smtpRelays={data.smtpRelays}
            actionLoading={actionLoading}
            initialTab={initialDomainTab}
            onBack={() => setDomainMode('list')}
            onApplyDns={applyDns}
            onCheck={checkDomain}
            onSendTest={openTestModal}
            onPatchDomain={patchDomain}
            onCopy={copy}
            onDelete={deleteDomain}
          />
        );
      }
      return (
        <DomainsPage
          domains={data.domains}
          events={data.events}
          dnsCredentials={data.dnsCredentials}
          actionLoading={actionLoading}
          onViewDetail={viewDetail}
          onApplyDns={applyDns}
          onCheck={checkDomain}
          onSendTest={openTestModal}
          onDelete={deleteDomain}
          onAddDomain={() => setAddOpen(true)}
        />
      );
    }
    if (activeView === 'dns-api') {
      return (
        <DnsApi
          credentials={data.dnsCredentials}
          loading={actionLoading}
          onSave={saveDnsCredential}
          onTest={testDnsCredential}
          onDelete={deleteDnsCredential}
        />
      );
    }
    if (activeView === 'smtp') {
      return (
        <SmtpCredentials
          config={data.config}
          credential={data.smtpCredential}
          credentials={data.smtpCredentials}
          relays={data.smtpRelays}
          loading={actionLoading}
          onCopy={copy}
          onLoadCredential={loadSmtpLoginCredential}
          onSaveCredential={saveSmtpLoginCredential}
          onDeleteCredential={deleteSmtpLoginCredential}
          onLoadRelay={loadSmtpRelay}
          onSaveRelay={saveSmtpRelay}
          onDeleteRelay={deleteSmtpRelay}
        />
      );
    }
    if (activeView === 'inbox') {
      return (
        <Inbox
          config={data.config}
          domains={data.domains}
          mailboxes={data.inboundMailboxes}
          messages={data.inboundMessages}
          loading={actionLoading}
          onCreateMailbox={createInboundMailbox}
          onPatchDomain={patchDomain}
          onLoadMessages={loadInboundMessages}
          onLoadMessage={loadInboundMessage}
          onCopy={copy}
          onAddDomain={() => setAddOpen(true)}
        />
      );
    }
    if (activeView === 'tokens') {
      return (
        <ApiTokens
          tokens={data.apiTokens}
          config={data.config}
          loading={actionLoading}
          onCreate={createApiToken}
          onUpdate={updateApiToken}
          onRevoke={revokeApiToken}
          onCopy={copy}
        />
      );
    }
    if (activeView === 'logs') {
      return <SendingLogs events={data.events} domains={data.domains} onCopy={copy} onLoadEvent={loadSendEvent} />;
    }
    if (activeView === 'webhooks') {
      return <Webhooks domains={data.domains} onCopy={copy} />;
    }
    if (activeView === 'admin') {
      return <AdminPage me={data.me} />;
    }
    if (activeView === 'settings') {
      return (
        <Settings
          me={data.me}
          settings={data.settings}
          users={data.users}
          loading={actionLoading}
          onSave={saveSettings}
        />
      );
    }
    return <PlaceholderPage title={t(viewTitleKeys[activeView])} />;
  }
}

function relayLabel(relay: SmtpRelay, t: (key: string) => string) {
  return `${relay.name}${relay.isDefault ? ` · ${t('smtpRelay.default')}` : ''} · ${relay.host}:${relay.port}`;
}
