import { App as AntApp, ConfigProvider, Form, Input, Modal } from 'antd';
import { useEffect, useMemo, useState } from 'react';

import { AddDomainDrawer } from '../components/domain/AddDomainDrawer';
import { AdminLayout } from '../layouts/AdminLayout';
import AdminPage from '../pages/Admin';
import ApiTokens from '../pages/ApiTokens';
import Dashboard from '../pages/Dashboard';
import DnsApi from '../pages/DnsApi';
import DomainDetail from '../pages/Domains/DomainDetail';
import DomainsPage from '../pages/Domains';
import PlaceholderPage from '../pages/PlaceholderPage';
import SendingLogs from '../pages/SendingLogs';
import Settings from '../pages/Settings';
import SmtpCredentials from '../pages/SmtpCredentials';
import { I18nProvider, useI18n } from './i18n/react';
import { buildDnsApplyFeedback } from './domain-model.js';
import { api } from './services/api';
import './styles.css';
import type {
  AddDomainPayload,
  ApiToken,
  AppData,
  DnsCredential,
  Domain,
  DomainMode,
  DomainPatchPayload,
  RuntimeConfig,
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
  tokens: 'nav.tokens',
  logs: 'nav.logs',
  webhooks: 'nav.webhooks',
  admin: 'nav.admin',
  settings: 'nav.settings'
};

export default function App() {
  return (
    <ConfigProvider
      theme={{
        token: {
          colorPrimary: '#1677ff',
          borderRadius: 10,
          colorBgLayout: '#f5f7fb',
          colorBorderSecondary: '#e5eaf2'
        },
        components: {
          Card: {
            borderRadiusLG: 12
          },
          Table: {
            cellPaddingBlock: 14,
            cellPaddingInline: 14
          }
        }
      }}
    >
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
      const [config, domains, events, analytics, smtpCredential, dnsCredentials, apiTokens] = await Promise.all([
        api.config(),
        api.domains(),
        api.events(),
        api.analytics(30),
        api.smtpCredential(),
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
        analytics: analytics.analytics || null,
        smtpCredential: smtpCredential.credential || null,
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
      text: `This is a MailHub test message from ${domain.domain}.`
    });
  }

  async function submitTestMail() {
    if (!testDomain) return;
    const values = await testForm.validateFields();
    await runAction(async () => api.sendTest(testDomain.id, values), t('actions.testMailQueued'));
    setTestDomain(null);
    const [events, analytics] = await Promise.all([api.events(), api.analytics(30)]);
    setData((current) => ({ ...current, events: events.events || [], analytics: analytics.analytics || current.analytics }));
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

  async function saveSmtpCredential(values: { username: string; password?: string }) {
    const result = await runAction(async () => api.saveSmtpCredential(values), t('actions.smtpSaved'));
    if (!result?.credential) return;
    setData((current) => ({
      ...current,
      smtpCredential: result.credential,
      config: current.config?.submission
        ? {
            ...current.config,
            submission: {
              ...current.config.submission,
              username: result.credential.username,
              passwordSet: Boolean(result.credential.passwordSet)
            }
          }
        : current.config
    }));
  }

  async function createApiToken(name: string) {
    const result = await runAction(async () => api.createApiToken(name), t('tokens.createdSuccess'));
    if (!result?.token) return null;
    setData((current) => ({ ...current, apiTokens: [result.token, ...current.apiTokens] }));
    return result.token;
  }

  async function deleteApiToken(token: ApiToken) {
    const result = await runAction(async () => api.deleteApiToken(token.id), t('tokens.deletedSuccess'));
    if (!result?.deleted) return;
    setData((current) => ({ ...current, apiTokens: current.apiTokens.filter((item) => item.id !== token.id) }));
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
          loading={actionLoading}
          onCopy={copy}
          onSave={saveSmtpCredential}
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
          onDelete={deleteApiToken}
          onCopy={copy}
        />
      );
    }
    if (activeView === 'logs') {
      return <SendingLogs events={data.events} domains={data.domains} onCopy={copy} />;
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
