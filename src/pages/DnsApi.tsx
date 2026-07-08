import { DeleteOutlined, EditOutlined, ThunderboltOutlined } from '@ant-design/icons';
import { Button, Card, Form, Input, InputNumber, Popconfirm, Select, Space, Table, Tag, Typography } from 'antd';
import type { ColumnsType } from 'antd/es/table';
import { useState } from 'react';

import { useI18n } from '../frontend/i18n/react';
import type { DnsCredential } from '../frontend/types';

interface DnsApiProps {
  credentials: DnsCredential[];
  loading?: boolean;
  onSave: (values: Record<string, unknown>, id?: number) => Promise<void>;
  onTest: (credential: DnsCredential) => void;
  onDelete: (credential: DnsCredential) => void;
}

export default function DnsApi({ credentials, loading, onSave, onTest, onDelete }: DnsApiProps) {
  const { t } = useI18n();
  const [form] = Form.useForm();
  const [editing, setEditing] = useState<DnsCredential | null>(null);
  const provider = Form.useWatch('provider', form) || 'cloudflare';

  function edit(credential: DnsCredential) {
    setEditing(credential);
    form.setFieldsValue(credential);
  }

  async function submit(values: Record<string, unknown>) {
    await onSave(values, editing?.id);
    setEditing(null);
    form.resetFields();
    form.setFieldValue('provider', 'cloudflare');
    form.setFieldValue('defaultTtl', 600);
  }

  const columns: ColumnsType<DnsCredential> = [
    { title: t('tokens.name'), dataIndex: 'name' },
    { title: 'Provider', dataIndex: 'provider', render: providerLabel },
    { title: t('dnsApi.zone'), dataIndex: 'zoneName' },
    { title: 'TTL', dataIndex: 'defaultTtl' },
    { title: t('tokens.createdAt'), dataIndex: 'updatedAt', render: (value) => new Date(value).toLocaleString() },
    {
      title: t('domains.actions'),
      render: (_, credential) => (
        <Space wrap>
          <Button icon={<ThunderboltOutlined />} onClick={() => onTest(credential)}>
            {t('domains.test')}
          </Button>
          <Button icon={<EditOutlined />} onClick={() => edit(credential)}>
            {t('dnsApi.editTitle')}
          </Button>
          <Popconfirm title={t('tokens.deleteConfirm')} onConfirm={() => onDelete(credential)}>
            <Button danger icon={<DeleteOutlined />} />
          </Popconfirm>
        </Space>
      )
    }
  ];

  return (
    <Space direction="vertical" size={16} className="full-width">
      <Card title={t('dnsApi.title')} extra={<Tag>{credentials.length}</Tag>}>
        <Table rowKey="id" columns={columns} dataSource={credentials} scroll={{ x: 900 }} />
      </Card>
      <Card
        title={editing ? `${t('dnsApi.editTitle')} ${editing.name}` : t('dnsApi.createTitle')}
        extra={editing ? <Button onClick={() => { setEditing(null); form.resetFields(); }}>{t('common.cancel')}</Button> : null}
      >
        <Form
          form={form}
          layout="vertical"
          onFinish={submit}
          initialValues={{ provider: 'cloudflare', defaultTtl: 600 }}
        >
          <div className="form-grid two">
            <Form.Item name="name" label={t('tokens.name')} rules={[{ required: true, message: t('tokens.nameRequired') }]}>
              <Input placeholder="Primary Cloudflare" />
            </Form.Item>
            <Form.Item name="provider" label="Provider" rules={[{ required: true }]}>
              <Select
                options={[
                  { value: 'cloudflare', label: 'Cloudflare' },
                  { value: 'aliyun', label: 'Aliyun DNS' },
                  { value: 'dnspod', label: 'Tencent DNSPod' }
                ]}
              />
            </Form.Item>
            <Form.Item
              name="zoneName"
              label={t('dnsApi.zone')}
              rules={[{ required: true, message: t('dnsApi.zoneRequired') }]}
              extra={provider === 'cloudflare' ? t('dnsApi.cloudflareZoneExtra') : undefined}
            >
              <Input placeholder="example.com" />
            </Form.Item>
            <Form.Item name="defaultTtl" label="TTL">
              <InputNumber min={60} max={86400} className="full-width" />
            </Form.Item>
          </div>
          {provider === 'cloudflare' ? (
            <div className="form-grid two">
              <Form.Item name="apiToken" label="Cloudflare API Token" extra={editing ? t('dnsApi.keepSecret') : t('dnsApi.tokenExtra')}>
                <Input.Password autoComplete="off" />
              </Form.Item>
              <Form.Item name="zoneId" label="Cloudflare Zone ID">
                <Input autoComplete="off" />
              </Form.Item>
            </div>
          ) : null}
          {provider === 'aliyun' ? (
            <div className="form-grid two">
              <Form.Item name="accessKeyId" label="AccessKeyId" extra={editing ? t('dnsApi.keepSecret') : undefined}>
                <Input autoComplete="off" />
              </Form.Item>
              <Form.Item name="accessKeySecret" label="AccessKeySecret">
                <Input.Password autoComplete="off" />
              </Form.Item>
            </div>
          ) : null}
          {provider === 'dnspod' ? (
            <div className="form-grid two">
              <Form.Item name="secretId" label="SecretId" extra={editing ? t('dnsApi.keepSecret') : undefined}>
                <Input autoComplete="off" />
              </Form.Item>
              <Form.Item name="secretKey" label="SecretKey">
                <Input.Password autoComplete="off" />
              </Form.Item>
            </div>
          ) : null}
          <Space>
            <Button type="primary" htmlType="submit" loading={loading}>
              {editing ? t('dnsApi.save') : t('dnsApi.create')}
            </Button>
            <Typography.Text type="secondary">{t('dnsApi.secretHint')}</Typography.Text>
          </Space>
        </Form>
      </Card>
    </Space>
  );
}

function providerLabel(provider: string) {
  return {
    cloudflare: <Tag color="blue">Cloudflare</Tag>,
    aliyun: <Tag color="orange">Aliyun DNS</Tag>,
    dnspod: <Tag color="cyan">Tencent DNSPod</Tag>
  }[provider] || <Tag>{provider}</Tag>;
}
