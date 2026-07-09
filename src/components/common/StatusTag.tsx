import { Badge } from 'antd';

import { getRecordStatusMeta } from '../../frontend/domain-model.js';
import { useI18n } from '../../frontend/i18n/react';
import { StatusPill, type StatusTone } from './StatusPill';

interface StatusTagProps {
  status?: string;
  record?: { status?: string };
  label?: string;
  mode?: 'tag' | 'badge';
}

function colorToTone(color: string): StatusTone {
  switch (color) {
    case 'success':
      return 'success';
    case 'warning':
    case 'processing':
      return 'warning';
    case 'error':
      return 'error';
    default:
      return 'neutral';
  }
}

export function StatusTag({ status, record, label, mode = 'tag' }: StatusTagProps) {
  const { t } = useI18n();
  const meta = getRecordStatusMeta(record || { status });
  const text = label || t(`status.${meta.key}`);

  if (mode === 'badge') {
    return <Badge status={meta.color === 'default' ? 'default' : meta.color} text={text} />;
  }

  return <StatusPill tone={colorToTone(meta.color)}>{text}</StatusPill>;
}
