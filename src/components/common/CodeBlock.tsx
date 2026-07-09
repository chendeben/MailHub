import { CopyOutlined } from '@ant-design/icons';
import { Button, Typography } from 'antd';

export function CodeBlock({
  value,
  onCopy
}: {
  value: string;
  onCopy?: (value: string) => void;
}) {
  return (
    <div className="code-block">
      <Typography.Paragraph code className="code-block__value">
        {value}
      </Typography.Paragraph>
      {onCopy ? (
        <Button
          type="text"
          size="small"
          icon={<CopyOutlined />}
          className="code-block__copy"
          onClick={() => onCopy(value)}
          aria-label="Copy"
        />
      ) : null}
    </div>
  );
}
