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
import { api } from '../services/api';
import { authModeFromLocation, nextAuthSuccessState } from './auth-model';

type AuthMode = 'login' | 'register' | 'forgot' | 'reset' | 'resend';
type AlertKind = 'error' | 'success';

interface LoginValues {
  username: string;
  password: string;
}

interface RegisterValues extends LoginValues {
  email: string;
}

interface EmailValues {
  email: string;
}

interface ResetPasswordValues {
  password: string;
}

export function AuthApp() {
  const { locale, locales, setLocale, t } = useI18n();
  const initialAuth = authModeFromLocation(window.location.pathname, window.location.search);
  const [mode, setMode] = useState<AuthMode>(initialAuth.mode as AuthMode);
  const [resetToken, setResetToken] = useState(initialAuth.token);
  const [message, setMessage] = useState('');
  const [messageKind, setMessageKind] = useState<AlertKind>('error');
  const [loading, setLoading] = useState(false);
  const [loginForm] = Form.useForm<LoginValues>();
  const [registerForm] = Form.useForm<RegisterValues>();
  const [emailForm] = Form.useForm<EmailValues>();
  const [resetForm] = Form.useForm<ResetPasswordValues>();

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const error = params.get('error');
    if (error) {
      setMessage(error);
      setMessageKind('error');
      window.history.replaceState(null, '', window.location.pathname);
    }
    if (initialAuth.mode === 'reset' && !initialAuth.token) {
      setMessage(t('auth.resetTokenMissing'));
      setMessageKind('error');
    }
  }, []);

  const modeOptions = useMemo(() => [
    { label: t('auth.login'), value: 'login' },
    { label: t('auth.register'), value: 'register' }
  ], [t]);

  async function submit(path: string, values: LoginValues | RegisterValues) {
    setLoading(true);
    setMessage('');
    setMessageKind('error');
    try {
      const response = await fetch(path, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(values)
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(data.error || t('auth.requestFailed'));
      const next = nextAuthSuccessState(path, data);
      if (next.redirectTo) {
        window.location.href = next.redirectTo;
        return;
      }
      setAuthMode(next.mode as AuthMode);
      setMessage(next.message);
      setMessageKind('success');
    } catch (error) {
      setMessage(error instanceof Error ? error.message : t('auth.requestFailed'));
      setMessageKind('error');
    } finally {
      setLoading(false);
    }
  }

  async function submitAccountEmail(kind: 'forgot' | 'resend', values: EmailValues) {
    setLoading(true);
    setMessage('');
    setMessageKind('error');
    try {
      const result = kind === 'forgot'
        ? await api.forgotPassword(values.email)
        : await api.resendVerification(values.email);
      setMessage(result.message);
      setMessageKind('success');
    } catch (error) {
      setMessage(error instanceof Error ? error.message : t('auth.requestFailed'));
      setMessageKind('error');
    } finally {
      setLoading(false);
    }
  }

  async function submitResetPassword(values: ResetPasswordValues) {
    if (!resetToken) {
      setMessage(t('auth.resetTokenMissing'));
      setMessageKind('error');
      return;
    }
    setLoading(true);
    setMessage('');
    setMessageKind('error');
    try {
      const result = await api.resetPassword(resetToken, values.password);
      setAuthMode('login');
      setResetToken('');
      setMessage(result.message);
      setMessageKind('success');
      resetForm.resetFields();
    } catch (error) {
      setMessage(error instanceof Error ? error.message : t('auth.requestFailed'));
      setMessageKind('error');
    } finally {
      setLoading(false);
    }
  }

  function setAuthMode(nextMode: AuthMode) {
    setMode(nextMode);
    setMessage('');
    setMessageKind('error');
    window.history.replaceState(null, '', authPathForMode(nextMode));
  }

  return (
    <main className="auth-page">
      <section className="auth-brand-panel" aria-label="MailHub">
        <div className="auth-brand-top">
          <div className="brand-logo auth-logo" aria-hidden="true">MH</div>
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
                {mode === 'register' ? t('auth.registerEyebrow') : t('auth.loginEyebrow')}
              </Typography.Text>
              <Typography.Title level={2}>{authTitle(mode, t)}</Typography.Title>
            </div>

            {mode === 'login' || mode === 'register' ? (
              <Segmented
                block
                value={mode}
                options={modeOptions}
                onChange={(value) => setAuthMode(value as AuthMode)}
              />
            ) : null}

            {message ? <Alert type={messageKind} showIcon message={message} /> : null}

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
                <div className="auth-link-row">
                  <Button type="link" onClick={() => setAuthMode('forgot')}>
                    {t('auth.forgotPassword')}
                  </Button>
                  <Button type="link" onClick={() => setAuthMode('resend')}>
                    {t('auth.resendVerification')}
                  </Button>
                </div>
              </Form>
            ) : null}

            {mode === 'register' ? (
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
            ) : null}

            {mode === 'forgot' || mode === 'resend' ? (
              <Form
                form={emailForm}
                layout="vertical"
                onFinish={(values) => submitAccountEmail(mode, values)}
                requiredMark={false}
              >
                <Form.Item name="email" label={t('auth.email')} rules={[{ required: true, type: 'email', message: t('auth.email') }]}>
                  <Input prefix={<MailOutlined />} autoComplete="email" placeholder={t('auth.emailPlaceholder')} autoFocus />
                </Form.Item>
                <Button type="primary" htmlType="submit" loading={loading} block size="large">
                  {mode === 'forgot' ? t('auth.forgotPasswordButton') : t('auth.resendVerificationButton')}
                </Button>
                <Button type="link" block onClick={() => setAuthMode('login')}>
                  {t('auth.backToLogin')}
                </Button>
              </Form>
            ) : null}

            {mode === 'reset' ? (
              <Form form={resetForm} layout="vertical" onFinish={submitResetPassword} requiredMark={false}>
                <Form.Item name="password" label={t('auth.newPassword')} rules={[{ required: true, min: 8, message: t('auth.password') }]}>
                  <Input.Password prefix={<LockOutlined />} autoComplete="new-password" autoFocus />
                </Form.Item>
                <Button type="primary" htmlType="submit" loading={loading} block size="large" disabled={!resetToken}>
                  {t('auth.resetPasswordButton')}
                </Button>
                <Button type="link" block onClick={() => setAuthMode('login')}>
                  {t('auth.backToLogin')}
                </Button>
              </Form>
            ) : null}
          </Space>
        </Card>
      </section>
    </main>
  );
}

function authPathForMode(mode: AuthMode) {
  return {
    login: '/login',
    register: '/register',
    forgot: '/forgot-password',
    resend: '/resend-verification',
    reset: '/reset-password'
  }[mode];
}

function authTitle(mode: AuthMode, t: (key: string) => string) {
  return {
    login: t('auth.loginTitle'),
    register: t('auth.registerTitle'),
    forgot: t('auth.forgotPasswordTitle'),
    reset: t('auth.resetPasswordTitle'),
    resend: t('auth.resendVerificationTitle')
  }[mode];
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
