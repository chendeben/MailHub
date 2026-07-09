import { CheckOutlined } from '@ant-design/icons';
import { Button, Checkbox, Drawer, Form, Input, Select, Space, Steps, Typography } from 'antd';
import { useEffect, useState } from 'react';

import { useI18n } from '../../frontend/i18n/react';
import type { AddDomainPayload, DnsCredential, RuntimeConfig, SmtpRelay } from '../../frontend/types';

interface AddDomainDrawerProps {
  open: boolean;
  loading?: boolean;
  config: RuntimeConfig | null;
  dnsCredentials: DnsCredential[];
  smtpRelays: SmtpRelay[];
  onClose: () => void;
  onSubmit: (values: AddDomainPayload) => Promise<void>;
}

export function AddDomainDrawer({
  open,
  loading,
  config,
  dnsCredentials,
  smtpRelays,
  onClose,
  onSubmit
}: AddDomainDrawerProps) {
  const { t } = useI18n();
  const [form] = Form.useForm<AddDomainPayload>();
  const [current, setCurrent] = useState(0);
  const steps = [t('addDomain.stepDomain'), t('addDomain.stepDns'), t('addDomain.stepPolicy'), t('addDomain.stepConfirm')];

  useEffect(() => {
    if (!open) return;
    form.setFieldsValue({
      senderHost: config?.mailHostname || '',
      sendingIp: config?.sendingIp || '',
      selector: defaultSelector(),
      dmarcPolicy: config?.dmarcPolicy || 'none',
      spfExtra: config?.defaultSpfMechanisms || '',
      immediateCheck: true
    });
    setCurrent(0);
  }, [config, form, open]);

  async function next() {
    await form.validateFields(stepFields(current));
    setCurrent((value) => Math.min(value + 1, steps.length - 1));
  }

  async function submit() {
    const values = await form.validateFields();
    await onSubmit(values);
    form.resetFields();
    setCurrent(0);
  }

  return (
    <Drawer
      title={t('addDomain.title')}
      width={560}
      open={open}
      onClose={onClose}
      destroyOnHidden
      footer={
        <div className="drawer-footer">
          <Button onClick={onClose}>{t('common.cancel')}</Button>
          <Space>
            <Button disabled={current === 0} onClick={() => setCurrent((value) => value - 1)}>
              {t('common.previous')}
            </Button>
            {current < steps.length - 1 ? (
              <Button type="primary" onClick={next}>
                {t('common.next')}
              </Button>
            ) : (
              <Button type="primary" icon={<CheckOutlined />} loading={loading} onClick={submit}>
                {t('addDomain.create')}
              </Button>
            )}
          </Space>
        </div>
      }
    >
      <Space direction="vertical" size={24} className="full-width">
        <Steps current={current} items={steps.map((title) => ({ title }))} direction="vertical" responsive />
        <Form form={form} layout="vertical" requiredMark="optional">
          <div hidden={current !== 0}>
            <Form.Item
              name="domain"
              label={t('domains.domain')}
              rules={[{ required: true, message: t('addDomain.domainRequired') }]}
              extra={t('addDomain.domainExtra')}
            >
              <Input placeholder="example.com" autoComplete="off" />
            </Form.Item>
            <Form.Item name="senderHost" label={t('domains.senderHost')} rules={[{ required: true, message: t('addDomain.senderHostRequired') }]}>
              <Input placeholder="mail.example.com" autoComplete="off" />
            </Form.Item>
            <Form.Item name="sendingIp" label={t('domains.sendingIp')} rules={[{ required: true, message: t('addDomain.sendingIpRequired') }]}>
              <Input placeholder="203.0.113.10" autoComplete="off" />
            </Form.Item>
          </div>
          <div hidden={current !== 1}>
            <Form.Item
              name="dnsCredentialId"
              label={t('domains.dnsApi')}
              extra={t('addDomain.dnsExtra')}
            >
              <Select
                allowClear
                placeholder={t('addDomain.manualDns')}
                options={dnsCredentials.map((credential) => ({
                  value: credential.id,
                  label: `${credential.name} · ${providerLabel(credential.provider)}`
                }))}
              />
            </Form.Item>
            <Typography.Paragraph type="secondary">
              {t('addDomain.dnsHint')}
            </Typography.Paragraph>
            <Form.Item
              name="smtpRelayId"
              label={t('smtpRelay.domainDefault')}
              extra={t('smtpRelay.domainDefaultExtra')}
            >
              <Select
                allowClear
                placeholder={t('smtpRelay.useResolutionOrder')}
                options={smtpRelays.map((relay) => ({
                  value: relay.id,
                  label: relayLabel(relay, t)
                }))}
              />
            </Form.Item>
          </div>
          <div hidden={current !== 2}>
            <Form.Item name="selector" label="DKIM selector" rules={[{ required: true, message: t('addDomain.selectorRequired') }]}>
              <Input placeholder="mh202607" autoComplete="off" />
            </Form.Item>
            <Form.Item name="dmarcPolicy" label="DMARC">
              <Select
                options={[
                  { value: 'none', label: 'none' },
                  { value: 'quarantine', label: 'quarantine' },
                  { value: 'reject', label: 'reject' }
                ]}
              />
            </Form.Item>
            <Form.Item name="spfExtra" label={t('addDomain.spfExtra')}>
              <Input.TextArea rows={3} placeholder="include:spf.mailjet.com include:amazonses.com" />
            </Form.Item>
          </div>
          <div hidden={current !== 3}>
            <Typography.Title level={5}>{t('addDomain.generatedTitle')}</Typography.Title>
            <ul className="confirm-list">
              <li>{t('addDomain.recordVerification')}</li>
              <li>{t('addDomain.recordDkim')}</li>
              <li>{t('addDomain.recordSpf')}</li>
              <li>{t('addDomain.recordDmarc')}</li>
              <li>{t('addDomain.recordSenderA')}</li>
              <li>{t('addDomain.recordPtr')}</li>
            </ul>
            <Form.Item name="immediateCheck" valuePropName="checked">
              <Checkbox>{t('addDomain.immediateCheck')}</Checkbox>
            </Form.Item>
          </div>
        </Form>
      </Space>
    </Drawer>
  );
}

function stepFields(step: number): Array<keyof AddDomainPayload> {
  if (step === 0) return ['domain', 'senderHost', 'sendingIp'];
  if (step === 1) return ['dnsCredentialId', 'smtpRelayId'];
  if (step === 2) return ['selector', 'dmarcPolicy', 'spfExtra'];
  return [];
}

function defaultSelector() {
  const date = new Date();
  return `mh${date.getUTCFullYear()}${String(date.getUTCMonth() + 1).padStart(2, '0')}`;
}

function providerLabel(provider: string) {
  return {
    cloudflare: 'Cloudflare',
    aliyun: 'Aliyun DNS',
    dnspod: 'Tencent DNSPod'
  }[provider] || provider;
}

function relayLabel(relay: SmtpRelay, t: (key: string) => string) {
  return `${relay.name}${relay.isDefault ? ` · ${t('smtpRelay.default')}` : ''} · ${relay.host}:${relay.port}`;
}
