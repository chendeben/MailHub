import {
  ApiOutlined,
  AppstoreOutlined,
  CloudServerOutlined,
  DashboardOutlined,
  GlobalOutlined,
  KeyOutlined,
  MailOutlined,
  ReloadOutlined,
  SendOutlined,
  SettingOutlined,
  UserOutlined
} from '@ant-design/icons';
import { Avatar, Breadcrumb, Button, Dropdown, Layout, Menu, Select, Space, Typography } from 'antd';
import type { ReactNode } from 'react';

import { useI18n } from '../frontend/i18n/react';
import type { User, ViewKey } from '../frontend/types';

const { Header, Sider, Content } = Layout;

const navItems: Array<{ key: ViewKey; labelKey: string; icon: ReactNode }> = [
  { key: 'dashboard', labelKey: 'nav.dashboard', icon: <DashboardOutlined /> },
  { key: 'domains', labelKey: 'nav.domains', icon: <GlobalOutlined /> },
  { key: 'dns-api', labelKey: 'nav.dnsApi', icon: <CloudServerOutlined /> },
  { key: 'smtp', labelKey: 'nav.smtp', icon: <MailOutlined /> },
  { key: 'tokens', labelKey: 'nav.tokens', icon: <KeyOutlined /> },
  { key: 'logs', labelKey: 'nav.logs', icon: <SendOutlined /> },
  { key: 'webhooks', labelKey: 'nav.webhooks', icon: <ApiOutlined /> },
  { key: 'settings', labelKey: 'nav.settings', icon: <SettingOutlined /> }
];

interface AdminLayoutProps {
  activeView: ViewKey;
  breadcrumb: string[];
  user: User | null;
  runtimeLine: string;
  loading: boolean;
  children: ReactNode;
  onViewChange: (view: ViewKey) => void;
  onRefresh: () => void;
  onAddDomain: () => void;
  onLogout: () => void;
}

export function AdminLayout({
  activeView,
  breadcrumb,
  user,
  runtimeLine,
  loading,
  children,
  onViewChange,
  onRefresh,
  onAddDomain,
  onLogout
}: AdminLayoutProps) {
  const { locale, locales, setLocale, t } = useI18n();

  return (
    <Layout className="admin-layout">
      <Sider breakpoint="lg" collapsedWidth={0} width={248} className="admin-sider">
        <div className="brand">
          <div className="brand-logo">MH</div>
          <div>
            <div className="brand-title">MailHub</div>
            <div className="brand-subtitle">Email Delivery</div>
          </div>
        </div>
        <Menu
          theme="dark"
          mode="inline"
          selectedKeys={[activeView]}
          items={navItems.map((item) => ({ key: item.key, icon: item.icon, label: t(item.labelKey) }))}
          onClick={({ key }) => onViewChange(key as ViewKey)}
        />
      </Sider>
      <Layout>
        <Header className="admin-header">
          <div className="header-title">
            <Breadcrumb items={breadcrumb.map((title) => ({ title }))} />
            <Typography.Text type="secondary" className="runtime-line">
              {runtimeLine}
            </Typography.Text>
          </div>
          <Space wrap>
            <Select
              aria-label="Language"
              value={locale}
              options={locales}
              onChange={setLocale}
              className="language-select"
            />
            <Button icon={<ReloadOutlined />} loading={loading} onClick={onRefresh}>
              {t('common.refresh')}
            </Button>
            <Button type="primary" icon={<AppstoreOutlined />} onClick={onAddDomain}>
              {t('common.addDomain')}
            </Button>
            <Dropdown
              menu={{
                items: [
                  { key: 'profile', label: user?.email || user?.username || t('common.account'), disabled: true },
                  { key: 'logout', label: t('common.logout'), onClick: onLogout }
                ]
              }}
            >
              <Button className="user-button">
                <Space>
                  <Avatar size={24} icon={<UserOutlined />} />
                  <span>{user?.username || t('common.user')}</span>
                </Space>
              </Button>
            </Dropdown>
          </Space>
        </Header>
        <Content className="admin-content">{children}</Content>
      </Layout>
    </Layout>
  );
}
