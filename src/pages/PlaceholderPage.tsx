import { Card, Empty } from 'antd';

import { useI18n } from '../frontend/i18n/react';

export default function PlaceholderPage({ title }: { title: string }) {
  const { t } = useI18n();
  return (
    <Card>
      <Empty description={`${title} ${t('domainDetail.placeholder')}`} />
    </Card>
  );
}
