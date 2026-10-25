const elements = {
  authCard: document.querySelector('#auth-card'),
  dashboard: document.querySelector('#dashboard'),
  dashboardHeading: document.querySelector('#dashboard-heading'),
  dashboardMessage: document.querySelector('#dashboard-message'),
  message: document.querySelector('#message'),
  authKicker: document.querySelector('#auth-kicker'),
  authHeading: document.querySelector('#auth-heading'),
  authSubtitle: document.querySelector('#auth-subtitle'),
  loginTab: document.querySelector('#login-tab'),
  registerTab: document.querySelector('#register-tab'),
  loginForm: document.querySelector('#login-form'),
  registerForm: document.querySelector('#register-form'),
  loginUsername: document.querySelector('#login-username'),
  loginPassword: document.querySelector('#login-password'),
  registerUsername: document.querySelector('#register-username'),
  registerPassword: document.querySelector('#register-password'),
  registerConfirm: document.querySelector('#register-confirm'),
  logoutButton: document.querySelector('#logout-button'),
  currentUsername: document.querySelector('#current-username'),
  avatar: document.querySelector('#avatar'),
  memberSince: document.querySelector('#member-since'),
  sessionExpiry: document.querySelector('#session-expiry'),
};

const state = {
  activeTab: 'login',
  busy: false,
  csrfToken: '',
  user: null,
};

class ApiError extends Error {
  constructor(message, status, code, retryAfter) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.code = code;
    this.retryAfter = retryAfter;
  }
}

bindEvents();
elements.dashboardHeading.tabIndex = -1;
refreshSession().catch(handleRequestError);

function bindEvents() {
  elements.loginTab.addEventListener('click', () => selectTab('login'));
  elements.registerTab.addEventListener('click', () => selectTab('register'));
  elements.loginTab.addEventListener('keydown', handleTabKeydown);
  elements.registerTab.addEventListener('keydown', handleTabKeydown);
  elements.loginForm.addEventListener('submit', handleLoginSubmit);
  elements.registerForm.addEventListener('submit', handleRegisterSubmit);
  elements.logoutButton.addEventListener('click', handleLogout);

  for (const toggle of document.querySelectorAll('[data-password-toggle]')) {
    toggle.addEventListener('click', handlePasswordToggle);
  }
}

function handleTabKeydown(event) {
  const keys = ['ArrowLeft', 'ArrowRight', 'Home', 'End'];
  if (!keys.includes(event.key)) return;

  event.preventDefault();

  let nextTab = state.activeTab;
  if (event.key === 'Home') nextTab = 'login';
  if (event.key === 'End') nextTab = 'register';
  if (event.key === 'ArrowLeft' || event.key === 'ArrowRight') {
    nextTab = state.activeTab === 'login' ? 'register' : 'login';
  }

  selectTab(nextTab, true);
}

function selectTab(tab, focus = false) {
  if (tab !== 'login' && tab !== 'register') return;

  state.activeTab = tab;
  const isLogin = tab === 'login';

  elements.loginTab.classList.toggle('is-active', isLogin);
  elements.registerTab.classList.toggle('is-active', !isLogin);
  elements.loginTab.setAttribute('aria-selected', String(isLogin));
  elements.registerTab.setAttribute('aria-selected', String(!isLogin));
  elements.loginTab.tabIndex = isLogin ? 0 : -1;
  elements.registerTab.tabIndex = isLogin ? -1 : 0;

  elements.loginForm.hidden = !isLogin;
  elements.registerForm.hidden = isLogin;

  elements.authKicker.textContent = isLogin ? 'Secure access' : 'New account';
  elements.authHeading.textContent = isLogin ? 'Welcome back' : 'Create your account';
  elements.authSubtitle.textContent = isLogin
    ? 'Sign in to continue to your account.'
    : 'Choose a username and a strong password to get started.';

  clearMessage();

  if (focus) {
    (isLogin ? elements.loginUsername : elements.registerUsername).focus();
  }
}

function handlePasswordToggle(event) {
  event.preventDefault();
  const button = event.currentTarget;
  const input = document.getElementById(button.dataset.passwordToggle);
  if (!input) return;

  const shouldShow = input.type === 'password';
  input.type = shouldShow ? 'text' : 'password';
  button.textContent = shouldShow ? 'Hide' : 'Show';
  button.setAttribute('aria-label', `${shouldShow ? 'Hide' : 'Show'} password`);
}

async function handleLoginSubmit(event) {
  event.preventDefault();
  if (state.busy) return;

  const username = elements.loginUsername.value.trim();
  const password = elements.loginPassword.value;

  if (!username || !password) {
    showMessage('Enter your username and password.', 'error');
    return;
  }

  clearMessage();
  setFormBusy(elements.loginForm, true);

  try {
    const data = await authRequest('/api/login', { username, password });
    applyAuthenticatedSession(data);
    elements.loginForm.reset();
    resetPasswordToggles();
  } catch (error) {
    handleRequestError(error);
  } finally {
    setFormBusy(elements.loginForm, false);
  }
}

async function handleRegisterSubmit(event) {
  event.preventDefault();
  if (state.busy) return;

  const username = elements.registerUsername.value.trim();
  const password = elements.registerPassword.value;
  const confirmation = elements.registerConfirm.value;

  if (!/^[A-Za-z0-9_]{3,32}$/.test(username)) {
    showMessage('Use 3-32 letters, numbers, or underscores for your username.', 'error');
    return;
  }

  if (password.length < 12) {
    showMessage('Use a password with at least 12 characters.', 'error');
    return;
  }

  if (password !== confirmation) {
    showMessage('Passwords do not match.', 'error');
    return;
  }

  clearMessage();
  setFormBusy(elements.registerForm, true);

  try {
    const data = await authRequest('/api/register', { username, password });
    applyAuthenticatedSession(data);
    showDashboardMessage('Account created. Welcome to Aegis.', 'success');
    elements.registerForm.reset();
    resetPasswordToggles();
  } catch (error) {
    handleRequestError(error);
  } finally {
    setFormBusy(elements.registerForm, false);
  }
}

async function handleLogout() {
  if (state.busy) return;

  clearMessage();
  state.busy = true;
  elements.logoutButton.disabled = true;
  const originalLabel = elements.logoutButton.textContent;
  elements.logoutButton.textContent = 'Signing out...';

  try {
    const data = await authRequest('/api/logout', {});
    state.user = null;
    state.csrfToken = data.csrfToken;
    showDashboardMessage('', 'success');
    showAuthView();
    selectTab('login');
    showMessage('You have been signed out.', 'success');
    elements.loginUsername.focus();
  } catch (error) {
    showDashboardMessage(
      error instanceof ApiError ? error.message : 'Unable to sign out. Please try again.',
      'error',
    );
  } finally {
    state.busy = false;
    elements.logoutButton.disabled = false;
    elements.logoutButton.textContent = originalLabel;
  }
}

function applyAuthenticatedSession(data) {
  state.user = data.user;
  state.csrfToken = data.csrfToken;
  showDashboardView(data);
}

function showAuthView() {
  elements.dashboard.hidden = true;
  elements.authCard.hidden = false;
}

function showDashboardView(data) {
  const user = data.user ?? state.user;
  if (!user) {
    showAuthView();
    return;
  }

  elements.authCard.hidden = true;
  elements.dashboard.hidden = false;
  elements.currentUsername.textContent = user.username;
  elements.avatar.textContent = user.username.slice(0, 1).toUpperCase();
  elements.memberSince.textContent = formatDate(user.createdAt);
  elements.sessionExpiry.textContent = formatDateTime(data.expiresAt);
  elements.dashboardHeading.focus();
}

async function refreshSession() {
  const response = await fetch('/api/session', {
    method: 'GET',
    credentials: 'same-origin',
    cache: 'no-store',
    headers: { Accept: 'application/json' },
  });

  const data = await readJson(response);
  if (!response.ok || !data) {
    throw new ApiError(
      data?.error || 'Unable to start a secure session.',
      response.status,
      data?.code,
    );
  }

  state.csrfToken = data.csrfToken;
  state.user = data.user;

  if (data.authenticated && data.user) {
    showDashboardView(data);
  } else {
    state.user = null;
    showAuthView();
  }

  return data;
}

async function authRequest(path, payload) {
  let response = await sendJson(path, payload);
  let data = await readJson(response);

  if (
    response.status === 403 &&
    (data?.code === 'SESSION_REQUIRED' || data?.code === 'CSRF_INVALID')
  ) {
    await refreshSession();
    response = await sendJson(path, payload);
    data = await readJson(response);
  }

  if (!response.ok) {
    throw new ApiError(
      data?.error || 'The request could not be completed.',
      response.status,
      data?.code,
      response.headers.get('Retry-After'),
    );
  }

  if (!data) {
    throw new ApiError('The server returned an invalid response.', response.status);
  }

  return data;
}

function sendJson(path, payload) {
  return fetch(path, {
    method: 'POST',
    credentials: 'same-origin',
    cache: 'no-store',
    headers: {
      Accept: 'application/json',
      'Content-Type': 'application/json',
      'X-CSRF-Token': state.csrfToken,
    },
    body: JSON.stringify(payload),
  });
}

async function readJson(response) {
  return response.json().catch(() => null);
}

function setFormBusy(form, busy) {
  state.busy = busy;
  form.setAttribute('aria-busy', String(busy));
  const button = form.querySelector('button[type="submit"]');
  if (button) {
    button.disabled = busy;
    button.classList.toggle('is-loading', busy);
  }
}

function resetPasswordToggles() {
  for (const toggle of document.querySelectorAll('[data-password-toggle]')) {
    const input = document.getElementById(toggle.dataset.passwordToggle);
    if (input) input.type = 'password';
    toggle.textContent = 'Show';
    toggle.setAttribute('aria-label', 'Show password');
  }
}

function showMessage(text, type = 'error') {
  elements.message.textContent = text;
  elements.message.classList.remove('message--error', 'message--success');
  elements.message.classList.add(`message--${type}`, 'is-visible');
}

function clearMessage() {
  elements.message.textContent = '';
  elements.message.classList.remove('is-visible', 'message--error', 'message--success');
}

function showDashboardMessage(text, type = 'error') {
  elements.dashboardMessage.textContent = text;
  elements.dashboardMessage.classList.remove('message--error', 'message--success');
  if (text) {
    elements.dashboardMessage.classList.add(`message--${type}`, 'is-visible');
  } else {
    elements.dashboardMessage.classList.remove('is-visible');
  }
}

function handleRequestError(error) {
  if (error instanceof ApiError) {
    showMessage(error.message, 'error');
    return;
  }

  showMessage('Unable to reach the server. Check your connection and try again.', 'error');
}

function formatDate(timestamp) {
  if (!Number.isFinite(timestamp)) return '—';

  return new Intl.DateTimeFormat(undefined, {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
  }).format(new Date(timestamp));
}

function formatDateTime(timestamp) {
  if (!Number.isFinite(timestamp)) return '—';

  return new Intl.DateTimeFormat(undefined, {
    month: 'short',
    day: 'numeric',
    hour: 'numeric',
    minute: '2-digit',
  }).format(new Date(timestamp));
}
