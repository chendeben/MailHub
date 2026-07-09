import { Space } from 'antd';

import { EmptyState } from '../components/common/EmptyState';
import { PageHeader } from '../components/common/PageHeader';
import { SectionCard } from '../components/common/SectionCard';
import { useI18n } from '../frontend/i18n/react';

export default function PlaceholderPage({ title }: { title: string }) {
  const { t } = useI18n();
  return (
    <Space direction="vertical" size={20} className="full-width">
      <PageHeader title={title} />
      <SectionCard>
        <EmptyState description={`${title} ${t('domainDetail.placeholder')}`} />
      </SectionCard>
    </Space>
  );
}
