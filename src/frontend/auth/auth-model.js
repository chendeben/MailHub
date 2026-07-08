export function nextAuthSuccessState(path, data = {}) {
  if (isRegisterPath(path)) {
    return {
      mode: 'login',
      path: '/login',
      message: String(data.message || '注册成功，请先验证邮箱，验证后等待管理员审核。'),
      redirectTo: ''
    };
  }
  return {
    mode: 'login',
    path: '/login',
    message: '',
    redirectTo: '/'
  };
}

export function authModeFromLocation(pathname, search = '') {
  const path = String(pathname || '');
  if (path.endsWith('/register')) return { mode: 'register', token: '' };
  if (path.endsWith('/forgot-password')) return { mode: 'forgot', token: '' };
  if (path.endsWith('/resend-verification')) return { mode: 'resend', token: '' };
  if (path.endsWith('/reset-password')) {
    return {
      mode: 'reset',
      token: new URLSearchParams(String(search || '')).get('token') || ''
    };
  }
  return { mode: 'login', token: '' };
}

function isRegisterPath(path) {
  return String(path || '').endsWith('/register');
}
