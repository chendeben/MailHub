import { createRoot } from 'react-dom/client';
import { App as AntApp, ConfigProvider } from 'antd';

import { I18nProvider } from '../i18n/react';
import '../styles.css';
import { mailhubTheme } from '../theme';
import { AuthApp } from './AuthApp';

createRoot(document.getElementById('auth-root')!).render(
  <ConfigProvider theme={mailhubTheme}>
    <AntApp>
      <I18nProvider>
        <AuthApp />
      </I18nProvider>
    </AntApp>
  </ConfigProvider>
);
