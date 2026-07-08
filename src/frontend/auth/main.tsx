import { createRoot } from 'react-dom/client';
import { App as AntApp, ConfigProvider } from 'antd';

import { I18nProvider } from '../i18n/react';
import '../styles.css';
import { AuthApp } from './AuthApp';

createRoot(document.getElementById('auth-root')!).render(
  <ConfigProvider
    theme={{
      token: {
        colorPrimary: '#1677ff',
        borderRadius: 10,
        colorBgLayout: '#f5f7fb',
        colorBorderSecondary: '#e5eaf2'
      },
      components: {
        Card: {
          borderRadiusLG: 12
        }
      }
    }}
  >
    <AntApp>
      <I18nProvider>
        <AuthApp />
      </I18nProvider>
    </AntApp>
  </ConfigProvider>
);
