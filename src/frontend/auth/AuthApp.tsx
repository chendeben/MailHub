import {
  ApiOutlined,
  CloudSyncOutlined,
  LockOutlined,
  MailOutlined,
  SafetyCertificateOutlined,
  UserOutlined
} from '@ant-design/icons';
import { Alert, Button, Card, Form, Input, Segmented, Select, Space, Typography } from 'antd';
import { useEffect, useMemo, useState, type ReactNode } from 'react';

import { useI18n } from '../i18n/react';

type AuthMode = 'login' | 'register';

interface LoginValues {
  username: string;
  password: string;
}

interface RegisterValues extends LoginValues {
  email: string;
}

export function AuthApp() {
  const { locale, locales, setLocale, t } = useI18n();
  const [mode, setMode] = useState<AuthMode>(() => window.location.pathname === '/register' ? 'register' : 'login');
  const [message, setMessage] = useState('');
  const [loading, setLoading] = useState(false);
  const [loginForm] = Form.useForm<LoginValues>();
  const [registerForm] = Form.useForm<RegisterValues>();

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const error = params.get('error');
    if (error) {
      setMessage(error);
      window.history.replaceState(null, '', window.location.pathname);
    }
  }, []);

  const modeOptions = useMemo(() => [
    { label: t('auth.login'), value: 'login' },
    { label: t('auth.register'), value: 'register' }
  ], [t]);

  async function submit(path: string, values: LoginValues | RegisterValues) {
    setLoading(true);
    setMessage('');
    try {
      const response = await fetch(path, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(values)
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(data.error || t('auth.requestFailed'));
      window.location.href = '/';
    } catch (error) {
      setMessage(error instanceof Error ? error.message : t('auth.requestFailed'));
    } finally {
      setLoading(false);
    }
  }

  return (
    <main className="auth-page">
      <section className="auth-brand-panel">
        <div className="auth-brand-top">
          <div className="brand-logo auth-logo">MH</div>
          <div>
            <Typography.Title level={1}>MailHub</Typography.Title>
            <Typography.Text>{t('auth.subtitle')}</Typography.Text>
          </div>
        </div>
        <div className="auth-signal-list">
          <Signal icon={<CloudSyncOutlined />} title="DNS" text={t('auth.valueDns')} />
          <Signal icon={<SafetyCertificateOutlined />} title="SMTP" text={t('auth.valueIsolation')} />
          <Signal icon={<ApiOutlined />} title="API" text={t('auth.valueObservability')} />
        </div>
      </section>

      <section className="auth-form-panel">
        <div className="auth-language-row">
          <Select value={locale} options={locales} onChange={setLocale} className="language-select" />
        </div>
        <Card className="auth-card">
          <Space direction="vertical" size={22} className="full-width">
            <div className="auth-heading">
              <Typography.Text className="auth-eyebrow">
                {mode === 'login' ? t('auth.loginEyebrow') : t('auth.registerEyebrow')}
              </Typography.Text>
              <Typography.Title level={2}>
                {mode === 'login' ? t('auth.loginTitle') : t('auth.registerTitle')}
              </Typography.Title>
            </div>

            <Segmented
              block
              value={mode}
              options={modeOptions}
              onChange={(value) => {
                const nextMode = value as AuthMode;
                setMode(nextMode);
                setMessage('');
                window.history.replaceState(null, '', nextMode === 'register' ? '/register' : '/login');
              }}
            />

            {message ? <Alert type="error" showIcon message={message} /> : null}

            {mode === 'login' ? (
              <Form form={loginForm} layout="vertical" onFinish={(values) => submit('/api/login', values)} requiredMark={false}>
                <Form.Item name="username" label={t('auth.usernameOrEmail')} rules={[{ required: true, message: t('auth.usernameOrEmail') }]}>
                  <Input prefix={<UserOutlined />} autoComplete="username" autoFocus />
                </Form.Item>
                <Form.Item name="password" label={t('auth.password')} rules={[{ required: true, message: t('auth.password') }]}>
                  <Input.Password prefix={<LockOutlined />} autoComplete="current-password" />
                </Form.Item>
                <Button type="primary" htmlType="submit" loading={loading} block size="large">
                  {t('auth.submitLogin')}
                </Button>
              </Form>
            ) : (
              <Form form={registerForm} layout="vertical" onFinish={(values) => submit('/api/register', values)} requiredMark={false}>
                <Form.Item name="username" label={t('auth.username')} rules={[{ required: true, min: 3, message: t('auth.username') }]}>
                  <Input prefix={<UserOutlined />} autoComplete="username" autoFocus />
                </Form.Item>
                <Form.Item name="email" label={t('auth.email')} rules={[{ required: true, type: 'email', message: t('auth.email') }]}>
                  <Input prefix={<MailOutlined />} autoComplete="email" placeholder={t('auth.emailPlaceholder')} />
                </Form.Item>
                <Form.Item name="password" label={t('auth.password')} rules={[{ required: true, min: 8, message: t('auth.password') }]}>
                  <Input.Password prefix={<LockOutlined />} autoComplete="new-password" />
                </Form.Item>
                <Button type="primary" htmlType="submit" loading={loading} block size="large">
                  {t('auth.registerButton')}
                </Button>
              </Form>
            )}
          </Space>
        </Card>
      </section>
    </main>
  );
}

function Signal({ icon, title, text }: { icon: ReactNode; title: string; text: string }) {
  return (
    <div className="auth-signal-item">
      <span>{icon}</span>
      <div>
        <Typography.Text>{title}</Typography.Text>
        <Typography.Title level={5}>{text}</Typography.Title>
      </div>
    </div>
  );
}
