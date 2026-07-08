import { CopyOutlined, ReloadOutlined } from '@ant-design/icons';
import { Button, Card, Descriptions, Form, Input, Space, Tag, Typography } from 'antd';

import { useI18n } from '../frontend/i18n/react';
import type { RuntimeConfig, SmtpCredential } from '../frontend/types';

interface SmtpCredentialsProps {
  config: RuntimeConfig | null;
  credential: SmtpCredential | null;
  loading?: boolean;
  onCopy: (value: string) => void;
  onSave: (values: { username: string; password?: string }) => Promise<void>;
}

export default function SmtpCredentials({ config, credential, loading, onCopy, onSave }: SmtpCredentialsProps) {
  const { t } = useI18n();
  const [form] = Form.useForm();

  function generatePassword() {
    const bytes = new Uint8Array(24);
    crypto.getRandomValues(bytes);
    const password = btoa(String.fromCharCode(...bytes)).replace(/[+/=]/g, '').slice(0, 28);
    form.setFieldValue('password', password);
  }

  return (
    <Space direction="vertical" size={16} className="full-width">
      <Card title={t('smtp.connectionTitle')}>
        <Descriptions column={1}>
          <Descriptions.Item label="SMTP Host">{copyable(config?.submission?.host || '-', onCopy)}</Descriptions.Item>
          <Descriptions.Item label="SMTP Port">
            {(config?.submission?.ports || []).map((item) => <Tag key={item.port}>{item.port} · {item.protocol}</Tag>)}
          </Descriptions.Item>
          <Descriptions.Item label="TLS / SSL">{config?.submission?.tls ? 'TLS' : 'STARTTLS'}</Descriptions.Item>
          <Descriptions.Item label="Username">{copyable(credential?.username || config?.submission?.username || '-', onCopy)}</Descriptions.Item>
          <Descriptions.Item label="Password">
            {credential?.password ? copyable(credential.password, onCopy) : <Typography.Text type="secondary">{t('smtp.resetToCopy')}</Typography.Text>}
          </Descriptions.Item>
        </Descriptions>
      </Card>
      <Card title={t('smtp.updateTitle')}>
        <Form
          form={form}
          layout="vertical"
          onFinish={onSave}
          initialValues={{ username: credential?.username || config?.submission?.username || '' }}
        >
          <Form.Item name="username" label="Username" rules={[{ required: true, message: t('smtp.usernameRequired') }]}>
            <Input autoComplete="off" />
          </Form.Item>
          <Form.Item name="password" label="Password" extra={t('smtp.passwordExtra')}>
            <Input.Password autoComplete="new-password" />
          </Form.Item>
          <Space wrap>
            <Button icon={<ReloadOutlined />} onClick={generatePassword}>
              {t('smtp.regenerate')}
            </Button>
            <Button type="primary" htmlType="submit" loading={loading}>
              {t('smtp.save')}
            </Button>
          </Space>
        </Form>
      </Card>
    </Space>
  );
}

function copyable(value: string, onCopy: (value: string) => void) {
  return (
    <Space>
      <Typography.Text code>{value}</Typography.Text>
      <Button size="small" icon={<CopyOutlined />} onClick={() => onCopy(value)} />
    </Space>
  );
}
