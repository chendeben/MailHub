import { Button, Form, Input, Select, Space, Switch, Table, Typography } from 'antd';
import type { ColumnsType } from 'antd/es/table';

import { PageHeader } from '../components/common/PageHeader';
import { SectionCard } from '../components/common/SectionCard';
import { StatusPill, type StatusTone } from '../components/common/StatusPill';
import { StatusTag } from '../components/common/StatusTag';
import { getDnsCurrentValues } from '../frontend/domain-model.js';
import { useI18n } from '../frontend/i18n/react';
import type { DnsRecord, RuntimeConfig, User } from '../frontend/types';
import { adminUserStatusMeta } from './Admin/admin-model.js';

interface SettingsProps {
  me: User | null;
  settings: RuntimeConfig | null;
  users: User[];
  loading?: boolean;
  onSave: (values: Partial<RuntimeConfig>) => Promise<void>;
}

export default function Settings({ me, settings, users, loading, onSave }: SettingsProps) {
  const { t } = useI18n();
  if (me?.role !== 'admin') {
    return (
      <Space direction="vertical" size={20} className="full-width">
        <PageHeader title={t('nav.settings')} />
        <SectionCard>
          <Typography.Text type="secondary">{t('settings.noPermission')}</Typography.Text>
        </SectionCard>
      </Space>
    );
  }

  const columns: ColumnsType<User> = [
    { title: 'Username', dataIndex: 'username' },
    { title: 'Email', dataIndex: 'email' },
    {
      title: 'Role',
      dataIndex: 'role',
      render: (value: string) => (
        <StatusPill tone={value === 'admin' ? 'info' : 'neutral'}>
          {roleLabel(value)}
        </StatusPill>
      )
    },
    {
      title: 'Status',
      dataIndex: 'status',
      render: (value: string) => {
        const meta = adminUserStatusMeta(value);
        return <StatusPill tone={userStatusTone(meta.color)}>{meta.label}</StatusPill>;
      }
    }
  ];
  const checkColumns: ColumnsType<DnsRecord> = [
    { title: t('settings.checkItem'), dataIndex: 'label', width: 160 },
    { title: t('dnsRecord.hostname'), dataIndex: 'host', width: 180, render: (value) => <Typography.Text code>{value || '-'}</Typography.Text> },
    { title: t('dnsRecord.targetValue'), dataIndex: 'value', width: 220, render: (value) => <Typography.Text code>{value || '-'}</Typography.Text> },
    {
      title: t('dnsRecord.currentValue'),
      width: 260,
      render: (_, record) => {
        const values: string[] = getDnsCurrentValues(record);
        return values.length
          ? (
              <Space direction="vertical" size={4}>
                {values.map((value) => <Typography.Text key={value} code>{value}</Typography.Text>)}
              </Space>
            )
          : <Typography.Text type="secondary">{t('dnsRecord.emptyCurrent')}</Typography.Text>;
      }
    },
    { title: t('common.status'), width: 120, render: (_, record) => <StatusTag record={record} /> }
  ];
  const checkData = settings?.systemChecks?.ptr ? [settings.systemChecks.ptr] : [];

  return (
    <Space direction="vertical" size={20} className="full-width">
      <PageHeader title={t('nav.settings')} />

      <SectionCard title="System">
        <Form
          layout="vertical"
          initialValues={settings || undefined}
          onFinish={onSave}
          disabled={loading}
        >
          <div className="form-grid two">
            <Form.Item name="appBaseUrl" label="APP_BASE_URL">
              <Input />
            </Form.Item>
            <Form.Item name="mailHostname" label="MAIL_HOSTNAME">
              <Input />
            </Form.Item>
            <Form.Item name="sendingIp" label="SENDING_IP">
              <Input />
            </Form.Item>
            <Form.Item name="defaultSpfMechanisms" label="DEFAULT_SPF_MECHANISMS">
              <Input />
            </Form.Item>
            <Form.Item name="dmarcPolicy" label="DMARC_POLICY">
              <Select options={['none', 'quarantine', 'reject'].map((value) => ({ value, label: value }))} />
            </Form.Item>
            <Form.Item name="dmarcRua" label="DMARC_RUA">
              <Input />
            </Form.Item>
          </div>
          <Form.Item name="sendRequiresVerified" label="SEND_REQUIRES_VERIFIED" valuePropName="checked">
            <Switch />
          </Form.Item>
          <Button type="primary" htmlType="submit" loading={loading}>
            {t('settings.save')}
          </Button>
        </Form>
      </SectionCard>

      <SectionCard
        title={t('settings.deliveryChecks')}
        extra={
          settings?.systemChecks?.checkedAt
            ? <Typography.Text type="secondary">{new Date(settings.systemChecks.checkedAt).toLocaleString()}</Typography.Text>
            : null
        }
      >
        <Table
          rowKey="key"
          columns={checkColumns}
          dataSource={checkData}
          pagination={false}
          scroll={{ x: 940 }}
        />
      </SectionCard>

      <SectionCard title="Users">
        <Table rowKey="id" columns={columns} dataSource={users} />
      </SectionCard>
    </Space>
  );
}

function roleLabel(role: string) {
  if (role === 'admin') return '管理员';
  if (role === 'user') return '用户';
  return role || '-';
}

function userStatusTone(color: string): StatusTone {
  if (color === 'green' || color === 'success') return 'success';
  if (color === 'gold' || color === 'orange' || color === 'warning') return 'warning';
  if (color === 'red' || color === 'error') return 'error';
  if (color === 'blue' || color === 'processing') return 'info';
  return 'neutral';
}
