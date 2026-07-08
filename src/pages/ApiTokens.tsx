import { CopyOutlined, DeleteOutlined, KeyOutlined } from '@ant-design/icons';
import { Alert, Button, Card, Collapse, Descriptions, Form, Input, Modal, Popconfirm, Space, Table, Tag, Tooltip, Typography } from 'antd';
import type { ColumnsType } from 'antd/es/table';
import { useState } from 'react';

import {
  buildApiUsageExamples,
  canCopyFullApiToken,
  formatApiTokenPrefix,
  getCreatedApiTokenSecret
} from '../frontend/api-token-model.js';
import { useI18n } from '../frontend/i18n/react';
import type { ApiToken, RuntimeConfig } from '../frontend/types';

interface ApiTokensProps {
  tokens: ApiToken[];
  config: RuntimeConfig | null;
  loading?: boolean;
  onCreate: (name: string) => Promise<ApiToken | null | void>;
  onDelete: (token: ApiToken) => void;
  onCopy: (value: string) => void;
}

export default function ApiTokens({ tokens, config, loading, onCreate, onDelete, onCopy }: ApiTokensProps) {
  const { t } = useI18n();
  const [form] = Form.useForm<{ name: string }>();
  const [createdToken, setCreatedToken] = useState<ApiToken | null>(null);
  const endpoint = `${config?.appBaseUrl || window.location.origin}/api/send`;
  const examples = buildApiUsageExamples({
    endpoint,
    token: '<USER_API_TOKEN>',
    from: 'noreply@example.com',
    to: 'user@example.com'
  });

  const columns: ColumnsType<ApiToken> = [
    { title: t('tokens.name'), dataIndex: 'name' },
    {
      title: t('tokens.prefix'),
      dataIndex: 'tokenPrefix',
      render: (_, token) => <Typography.Text code>{formatApiTokenPrefix(token)}</Typography.Text>
    },
    { title: t('tokens.lastUsed'), dataIndex: 'lastUsedAt', render: (value) => value ? new Date(value).toLocaleString() : t('tokens.neverUsed') },
    { title: t('tokens.createdAt'), dataIndex: 'createdAt', render: (value) => new Date(value).toLocaleString() },
    {
      title: t('tokens.actions'),
      render: (_, token) => (
        <Space>
          <Tooltip title={t('tokens.copyPrefix')}>
            <Button icon={<CopyOutlined />} onClick={() => onCopy(token.tokenPrefix)} />
          </Tooltip>
          <Tooltip title={t('tokens.secretUnavailable')}>
            <Button disabled icon={<KeyOutlined />} />
          </Tooltip>
          <Popconfirm title={t('tokens.deleteConfirm')} onConfirm={() => onDelete(token)}>
            <Button danger icon={<DeleteOutlined />} />
          </Popconfirm>
        </Space>
      )
    }
  ];

  async function submit(values: { name: string }) {
    const token = await onCreate(values.name);
    if (token && canCopyFullApiToken(token)) setCreatedToken(token);
    form.resetFields();
  }

  return (
    <>
      <Space direction="vertical" size={16} className="full-width">
      <Card title={t('tokens.createTitle')}>
        <Form form={form} layout="inline" onFinish={submit}>
          <Form.Item name="name" rules={[{ required: true, message: t('tokens.nameRequired') }]}>
            <Input placeholder={t('tokens.namePlaceholder')} />
          </Form.Item>
          <Button type="primary" htmlType="submit" loading={loading}>
            {t('tokens.create')}
          </Button>
        </Form>
      </Card>
      <Card title={t('tokens.listTitle')} extra={<Tag>{tokens.length}</Tag>}>
        <Alert type="info" showIcon message={t('tokens.prefixOnlyHelp')} className="token-list-alert" />
        <Table rowKey="id" columns={columns} dataSource={tokens} scroll={{ x: 900 }} />
      </Card>
      <Card title={t('tokens.docsTitle')}>
        <Space direction="vertical" size={16} className="full-width">
          <Alert type="info" showIcon message={t('tokens.noTokenHint')} />
          <Descriptions column={1} bordered size="small">
            <Descriptions.Item label={t('tokens.endpoint')}>{copyable(endpoint, onCopy)}</Descriptions.Item>
            <Descriptions.Item label={t('tokens.authHeader')}>{copyable(t('tokens.authHeaderValue'), onCopy)}</Descriptions.Item>
            <Descriptions.Item label={t('tokens.contentType')}><Typography.Text code>application/json</Typography.Text></Descriptions.Item>
          </Descriptions>
          <Card size="small" title={t('tokens.requestFields')}>
            <ul className="api-doc-list">
              <li>{t('tokens.fieldFrom')}</li>
              <li>{t('tokens.fieldTo')}</li>
              <li>{t('tokens.fieldSubject')}</li>
              <li>{t('tokens.fieldText')}</li>
              <li>{t('tokens.fieldHtml')}</li>
            </ul>
          </Card>
          <Collapse
            defaultActiveKey={['curl']}
            items={[
              { key: 'curl', label: t('tokens.curlExample'), children: <CodeSample value={examples.curl} /> },
              { key: 'node', label: t('tokens.nodeExample'), children: <CodeSample value={examples.nodeFetch} /> },
              { key: 'body', label: t('tokens.requestExample'), children: <CodeSample value={examples.requestBody} /> },
              { key: 'response', label: t('tokens.responseExample'), children: <CodeSample value={examples.successResponse} /> }
            ]}
          />
          <Card size="small" title={t('tokens.securityTips')}>
            <ul className="api-doc-list">
              <li>{t('tokens.securityTipStore')}</li>
              <li>{t('tokens.securityTipRotate')}</li>
              <li>{t('tokens.securityTipDomain')}</li>
            </ul>
          </Card>
        </Space>
      </Card>
    </Space>
      <Modal
        title={t('tokens.createdTitle')}
        open={Boolean(createdToken)}
        onCancel={() => setCreatedToken(null)}
        footer={[
          <Button key="close" onClick={() => setCreatedToken(null)}>
            {t('common.cancel')}
          </Button>,
          <Button
            key="copy"
            type="primary"
            icon={<CopyOutlined />}
            onClick={() => {
              const secret = getCreatedApiTokenSecret(createdToken || {});
              if (secret) onCopy(secret);
            }}
          >
            {t('tokens.copyCreated')}
          </Button>
        ]}
      >
        <Space direction="vertical" size={16} className="full-width">
          <Alert type="warning" showIcon message={t('tokens.createdWarning')} />
          <Typography.Paragraph code copyable className="code-sample">
            {getCreatedApiTokenSecret(createdToken || {})}
          </Typography.Paragraph>
        </Space>
      </Modal>
    </>
  );
}

function copyable(value: string, onCopy: (value: string) => void) {
  return (
    <Space>
      <Typography.Text code className="inline-code-value">{value}</Typography.Text>
      <Button size="small" icon={<CopyOutlined />} onClick={() => onCopy(value)} />
    </Space>
  );
}

function CodeSample({ value }: { value: string }) {
  return (
    <Typography.Paragraph code copyable className="code-sample">
      {value}
    </Typography.Paragraph>
  );
}
