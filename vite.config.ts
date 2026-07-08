import react from '@vitejs/plugin-react';
import { rmSync } from 'node:fs';
import { resolve } from 'node:path';
import { defineConfig } from 'vite';

export default defineConfig({
  plugins: [
    {
      name: 'clean-generated-assets',
      apply: 'build',
      buildStart() {
        rmSync(resolve(__dirname, 'public/assets'), { recursive: true, force: true });
      }
    },
    react()
  ],
  publicDir: false,
  build: {
    outDir: 'public',
    emptyOutDir: false,
    sourcemap: false,
    rollupOptions: {
      input: {
        index: resolve(__dirname, 'index.html'),
        login: resolve(__dirname, 'login.html')
      }
    }
  },
  server: {
    proxy: {
      '/api': 'http://127.0.0.1:3000',
      '/logout': 'http://127.0.0.1:3000'
    }
  }
});
