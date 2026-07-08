const loginForm = document.querySelector('#loginForm');
const registerForm = document.querySelector('#registerForm');
const message = document.querySelector('#loginMessage');
const modeTitle = document.querySelector('#modeTitle');
const modeEyebrow = document.querySelector('#modeEyebrow');
const tabs = document.querySelectorAll('[data-mode]');
const initialParams = new URLSearchParams(window.location.search);
const initialError = initialParams.get('error');

if (window.location.search) {
  window.history.replaceState(null, '', window.location.pathname);
}

for (const tab of tabs) {
  tab.addEventListener('click', () => setMode(tab.dataset.mode));
}

loginForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  await submitAuth('/api/login', loginForm, loginForm.querySelector('button'));
});

registerForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  await submitAuth('/api/register', registerForm, registerForm.querySelector('button'));
});

if (window.location.pathname === '/register') setMode('register');
if (initialError) showError(initialError);

function setMode(mode) {
  const registering = mode === 'register';
  loginForm.classList.toggle('hidden', registering);
  registerForm.classList.toggle('hidden', !registering);
  modeTitle.textContent = registering ? '注册账号' : '登录控制台';
  modeEyebrow.textContent = registering ? 'Register' : 'Sign in';
  for (const tab of tabs) tab.classList.toggle('active', tab.dataset.mode === mode);
  message.textContent = '';
  message.className = 'login-message';
  const input = (registering ? registerForm : loginForm).querySelector('input');
  input?.focus();
}

async function submitAuth(path, form, button) {
  message.textContent = '';
  message.className = 'login-message';
  button.disabled = true;
  try {
    const payload = Object.fromEntries(new FormData(form).entries());
    const response = await fetch(path, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.error || '请求失败。');
    window.location.href = '/';
  } catch (error) {
    showError(error.message);
  } finally {
    button.disabled = false;
  }
}

function showError(text) {
  message.textContent = text;
  message.classList.add('error');
}
