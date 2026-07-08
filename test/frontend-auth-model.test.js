import assert from 'node:assert/strict';
import { test } from 'node:test';

import { authModeFromLocation, nextAuthSuccessState } from '../src/frontend/auth/auth-model.js';

test('registration success returns to login without navigating to the protected app', () => {
  assert.deepEqual(
    nextAuthSuccessState('/api/register', {
      user: { status: 'pending_email' },
      message: '注册成功，请先验证邮箱，验证后等待管理员审核。'
    }),
    {
      mode: 'login',
      path: '/login',
      message: '注册成功，请先验证邮箱，验证后等待管理员审核。',
      redirectTo: ''
    }
  );
});

test('login success still redirects to the protected app', () => {
  assert.deepEqual(
    nextAuthSuccessState('/api/login', {
      user: { status: 'active' }
    }),
    {
      mode: 'login',
      path: '/login',
      message: '',
      redirectTo: '/'
    }
  );
});

test('detects account recovery modes from auth routes', () => {
  assert.deepEqual(authModeFromLocation('/forgot-password'), { mode: 'forgot', token: '' });
  assert.deepEqual(authModeFromLocation('/resend-verification'), { mode: 'resend', token: '' });
  assert.deepEqual(authModeFromLocation('/reset-password', '?token=abc123'), { mode: 'reset', token: 'abc123' });
  assert.deepEqual(authModeFromLocation('/login'), { mode: 'login', token: '' });
  assert.deepEqual(authModeFromLocation('/register'), { mode: 'register', token: '' });
});
