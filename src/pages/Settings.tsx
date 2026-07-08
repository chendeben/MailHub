import { Button, Card, Form, Input, Select, Space, Switch, Table, Tag, Typography } from 'antd';
import type { ColumnsType } from 'antd/es/table';

import { useI18n } from '../frontend/i18n/react';
import type { RuntimeConfig, User } from '../frontend/types';

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
      <Card>
        <Typography.Text type="secondary">{t('settings.noPermission')}</Typography.Text>
      </Card>
    );
  }

  const columns: ColumnsType<User> = [
    { title: 'Username', dataIndex: 'username' },
    { title: 'Email', dataIndex: 'email' },
    { title: 'Role', dataIndex: 'role', render: (value) => <Tag>{value}</Tag> },
    { title: 'Status', dataIndex: 'status', render: (value) => <Tag color={value === 'active' ? 'success' : 'default'}>{value}</Tag> }
  ];

  return (
    <Space direction="vertical" size={16} className="full-width">
      <Card title="System">
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
      </Card>
      <Card title="Users">
        <Table rowKey="id" columns={columns} dataSource={users} />
      </Card>
    </Space>
  );
}
