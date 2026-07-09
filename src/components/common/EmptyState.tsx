import type { ReactNode } from 'react';
import { Empty } from 'antd';

export function EmptyState({
  description,
  action,
  icon
}: {
  description: ReactNode;
  action?: ReactNode;
  icon?: ReactNode;
}) {
  return (
    <div className="empty-state">
      <Empty image={icon || Empty.PRESENTED_IMAGE_SIMPLE} description={description}>
        {action}
      </Empty>
    </div>
  );
}
