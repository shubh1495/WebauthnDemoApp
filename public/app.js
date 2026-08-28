// WebAuthn Front-End Logic
let currentUser = null;

document.addEventListener('DOMContentLoaded', async () => {
  initWebAuthnSupportCheck();
  setupTabNavigation();
  await checkActiveSession();
  setupPasskeyAutofill();
});

// -------------------------------------------------------------
// 1. FEATURE DETECTION & SUPPORT CHECKS
// -------------------------------------------------------------
async function initWebAuthnSupportCheck() {
  const webauthnPill = document.getElementById('webauthn-support');
  const autofillPill = document.getElementById('autofill-support');

  if (window.PublicKeyCredential) {
    webauthnPill.innerHTML = `<span class="status-dot active"></span> WebAuthn Supported`;
  } else {
    webauthnPill.innerHTML = `<span class="status-dot error"></span> WebAuthn Unsupported`;
    showAlert('WebAuthn is not supported in this browser environment.', 'error');
  }

  if (window.PublicKeyCredential && PublicKeyCredential.isConditionalMediationAvailable) {
    try {
      const isCMA = await PublicKeyCredential.isConditionalMediationAvailable();
      if (isCMA) {
        autofillPill.innerHTML = `<span class="status-dot active"></span> Autofill / Passkeys Ready`;
      } else {
        autofillPill.innerHTML = `<span class="status-dot warning"></span> Autofill Unavailable`;
      }
    } catch (e) {
      autofillPill.innerHTML = `<span class="status-dot warning"></span> Autofill Check Failed`;
    }
  } else {
    autofillPill.innerHTML = `<span class="status-dot warning"></span> Autofill Unsupported`;
  }
}

// -------------------------------------------------------------
// 2. UI NAVIGATION & TABS
// -------------------------------------------------------------
function setupTabNavigation() {
  const navBtns = document.querySelectorAll('.nav-btn');
  navBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      const tabId = btn.getAttribute('data-tab');
      switchToTab(tabId);
    });
  });
}

function switchToTab(tabId) {
  document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
  document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));

  const activeBtn = document.querySelector(`.nav-btn[data-tab="${tabId}"]`);
  const activePane = document.getElementById(tabId);

  if (activeBtn) activeBtn.classList.add('active');
  if (activePane) activePane.classList.add('active');
}

function setAuthMode(mode) {
  const loginBtn = document.getElementById('btn-mode-login');
  const regBtn = document.getElementById('btn-mode-register');
  const loginForm = document.getElementById('form-login');
  const regForm = document.getElementById('form-register');

  if (mode === 'login') {
    loginBtn.classList.add('active');
    regBtn.classList.remove('active');
    loginForm.classList.remove('hidden');
    regForm.classList.add('hidden');
  } else {
    regBtn.classList.add('active');
    loginBtn.classList.remove('active');
    regForm.classList.remove('hidden');
    loginForm.classList.add('hidden');
  }
}

// -------------------------------------------------------------
// 3. REGISTRATION CEREMONY
// -------------------------------------------------------------
async function handleRegister(e) {
  e.preventDefault();
  const username = document.getElementById('reg-username').value.trim();
  const deviceName = document.getElementById('reg-devicename').value.trim() || 'My Passkey';

  if (!username) return showAlert('Username is required for registration', 'error');

  try {
    updateStepper(1);
    showAlert('Requesting registration options from Relying Party...', 'info');

    // Step 1: Request options from server
    const optionsRes = await fetch('/api/register/options', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username })
    });
    const optionsData = await optionsRes.json();

    if (!optionsRes.ok) throw new Error(optionsData.error || 'Failed to get options');

    logInspectorOptions(optionsData.options);
    updateStepper(2);

    // Step 2: Trigger WebAuthn API on browser
    showAlert('Touch fingerprint sensor or insert security key...', 'info');
    
    let registrationResponse;
    if (window.SimpleWebAuthnBrowser) {
      registrationResponse = await SimpleWebAuthnBrowser.startRegistration({
        optionsJSON: optionsData.options
      });
    } else {
      throw new Error('SimpleWebAuthnBrowser library bundle not loaded.');
    }

    logInspectorResponse(registrationResponse);
    decodeAndInspectResponse(registrationResponse, 'registration');
    updateStepper(3);

    // Step 3: Verify response on RP server
    showAlert('Verifying passkey signature on RP server...', 'info');
    const verifyRes = await fetch('/api/register/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username,
        deviceName,
        response: registrationResponse
      })
    });
    const verifyData = await verifyRes.json();

    if (verifyData.verified) {
      showAlert(`Passkey successfully registered for "${username}"!`, 'success');
      await checkActiveSession();
      switchToTab('dashboard-tab');
    } else {
      throw new Error(verifyData.error || 'Verification failed on server');
    }

  } catch (error) {
    console.error('Registration Error:', error);
    showAlert(`Registration Error: ${error.message}`, 'error');
  }
}

// -------------------------------------------------------------
// 4. AUTHENTICATION CEREMONY (SIGN IN)
// -------------------------------------------------------------
async function handleLogin(e) {
  if (e) e.preventDefault();
  const username = document.getElementById('login-username').value.trim();

  try {
    updateStepper(1);
    showAlert('Fetching sign-in challenge from server...', 'info');

    const optionsRes = await fetch('/api/login/options', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username })
    });
    const optionsData = await optionsRes.json();

    if (!optionsRes.ok) throw new Error(optionsData.error || 'Failed to fetch options');

    logInspectorOptions(optionsData.options);
    updateStepper(2);

    showAlert('Use biometrics or Passkey to sign in...', 'info');
    
    let authResponse;
    if (window.SimpleWebAuthnBrowser) {
      authResponse = await SimpleWebAuthnBrowser.startAuthentication({
        optionsJSON: optionsData.options
      });
    } else {
      throw new Error('SimpleWebAuthnBrowser library bundle not loaded.');
    }

    logInspectorResponse(authResponse);
    decodeAndInspectResponse(authResponse, 'authentication');
    updateStepper(3);

    showAlert('Verifying signature on server...', 'info');
    const verifyRes = await fetch('/api/login/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username,
        response: authResponse
      })
    });
    const verifyData = await verifyRes.json();

    if (verifyData.verified) {
      showAlert(`Welcome back, ${verifyData.user.username}! Signed in with Passkey. Counter updated: ${verifyData.newCounter}`, 'success');
      await checkActiveSession();
    } else {
      throw new Error(verifyData.error || 'Authentication signature verification failed');
    }

  } catch (error) {
    console.error('Login Error:', error);
    showAlert(`Sign-in Error: ${error.message}`, 'error');
  }
}

// 1-Click Discoverable Credential Login
async function handlePasskeyLogin() {
  document.getElementById('login-username').value = '';
  await handleLogin();
}

// Setup Passkey Conditional UI / Autofill
async function setupPasskeyAutofill() {
  if (!window.PublicKeyCredential || !PublicKeyCredential.isConditionalMediationAvailable) return;
  
  try {
    const isCMA = await PublicKeyCredential.isConditionalMediationAvailable();
    if (!isCMA) return;

    // Fetch options with no username filter
    const optionsRes = await fetch('/api/login/options', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({})
    });
    const optionsData = await optionsRes.json();

    if (!optionsRes.ok) return;

    if (window.SimpleWebAuthnBrowser) {
      const authResponse = await SimpleWebAuthnBrowser.startAuthentication({
        optionsJSON: optionsData.options,
        useConditionalMediation: true
      });

      if (authResponse) {
        const verifyRes = await fetch('/api/login/verify', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ response: authResponse })
        });
        const verifyData = await verifyRes.json();

        if (verifyData.verified) {
          showAlert(`Autofill Passkey Sign-in successful! Welcome ${verifyData.user.username}`, 'success');
          await checkActiveSession();
        }
      }
    }
  } catch (e) {
    // Conditional mediation standardly cancels if user types manually
  }
}

// -------------------------------------------------------------
// 5. USER SESSION & PASSKEY MANAGEMENT
// -------------------------------------------------------------
async function checkActiveSession() {
  try {
    const res = await fetch('/api/user/me');
    const data = await res.json();

    const inactiveView = document.getElementById('session-inactive-view');
    const activeView = document.getElementById('session-active-view');
    const badgeCount = document.getElementById('badge-count');

    if (data.authenticated && data.user) {
      currentUser = data.user;
      inactiveView.classList.add('hidden');
      activeView.classList.remove('hidden');

      document.getElementById('user-avatar').innerText = data.user.username.charAt(0).toUpperCase();
      document.getElementById('user-display-name').innerText = data.user.username;
      document.getElementById('user-passkey-count').innerText = data.user.credentials.length;
      badgeCount.innerText = data.user.credentials.length;

      renderPasskeyInventory(data.user.credentials);
    } else {
      currentUser = null;
      inactiveView.classList.remove('hidden');
      activeView.classList.add('hidden');
      badgeCount.innerText = '0';
      renderPasskeyInventory([]);
    }
  } catch (err) {
    console.error('Session check failed:', err);
  }
}

function renderPasskeyInventory(credentials) {
  const container = document.getElementById('passkeys-list');
  if (!credentials || credentials.length === 0) {
    container.innerHTML = `
      <div class="empty-state">
        <p>No passkeys registered for this account yet. Click "Add Passkey" or create an account to get started.</p>
      </div>
    `;
    return;
  }

  container.innerHTML = credentials.map(c => `
    <div class="cred-card">
      <div>
        <div class="cred-header">
          <span class="cred-title">🔑 ${escapeHtml(c.name || 'Passkey')}</span>
          <span class="badge">${c.deviceType || 'singleDevice'}</span>
        </div>
        <div class="cred-id">ID: ${c.id.substring(0, 24)}...</div>
      </div>

      <div class="cred-meta">
        <div><strong>Sign Counter:</strong> ${c.counter} updates</div>
        <div><strong>Transports:</strong> ${c.transports ? c.transports.join(', ') : 'internal/usb'}</div>
        <div><strong>Created:</strong> ${new Date(c.createdAt).toLocaleDateString()}</div>
      </div>

      <div style="display: flex; gap: 0.5rem; margin-top: 0.5rem;">
        <button class="btn btn-sm btn-secondary" style="flex: 1" onclick="testCredentialAuth('${escapeHtml(c.id)}')">Test Assertion</button>
        <button class="btn btn-sm btn-outline-danger" onclick="deletePasskey('${c.id}')">Delete</button>
      </div>
    </div>
  `).join('');
}

async function showAddPasskeyModal() {
  if (!currentUser) {
    switchToTab('auth-tab');
    setAuthMode('register');
    return showAlert('Please enter your username to add a passkey.', 'info');
  }

  const deviceName = prompt('Enter a label for this Passkey/Authenticator:', 'Secondary Security Key');
  if (deviceName === null) return;

  document.getElementById('reg-username').value = currentUser.username;
  document.getElementById('reg-devicename').value = deviceName;
  switchToTab('auth-tab');
  setAuthMode('register');
}

async function deletePasskey(credId) {
  if (!confirm('Are you sure you want to delete this passkey?')) return;

  try {
    const res = await fetch(`/api/credentials/${encodeURIComponent(credId)}`, {
      method: 'DELETE'
    });
    const data = await res.json();
    if (data.success) {
      showAlert('Passkey removed successfully.', 'success');
      await checkActiveSession();
    } else {
      throw new Error(data.error);
    }
  } catch (err) {
    showAlert(`Delete failed: ${err.message}`, 'error');
  }
}

async function handleLogout() {
  await fetch('/api/logout', { method: 'POST' });
  showAlert('Signed out successfully.', 'info');
  await checkActiveSession();
  switchToTab('auth-tab');
}

async function resetDatabase() {
  if (!confirm('Reset entire in-memory database and clear all passkeys?')) return;
  await fetch('/api/debug/reset', { method: 'POST' });
  showAlert('Database reset to clean state.', 'info');
  await checkActiveSession();
}

// -------------------------------------------------------------
// 6. PROTOCOL CEREMONY INSPECTOR & DECODER
// -------------------------------------------------------------
function updateStepper(stepNum) {
  const b1 = document.getElementById('step-1-badge');
  const b2 = document.getElementById('step-2-badge');
  const b3 = document.getElementById('step-3-badge');

  [b1, b2, b3].forEach(b => b.className = 'step-badge pending');

  if (stepNum >= 1) b1.className = 'step-badge active';
  if (stepNum >= 2) { b1.className = 'step-badge done'; b2.className = 'step-badge active'; }
  if (stepNum >= 3) { b2.className = 'step-badge done'; b3.className = 'step-badge done'; }
}

function logInspectorOptions(options) {
  document.getElementById('json-options').innerText = JSON.stringify(options, null, 2);
}

function logInspectorResponse(response) {
  document.getElementById('json-response').innerText = JSON.stringify(response, null, 2);
}

function decodeAndInspectResponse(response, ceremonyType) {
  try {
    const decodedObj = {};

    // Decode clientDataJSON
    if (response.response && response.response.clientDataJSON) {
      const rawClientData = atob(base64urlToBase64(response.response.clientDataJSON));
      decodedObj.clientDataJSON_Decoded = JSON.parse(rawClientData);
    }

    // Decode authenticatorData flags (for authentication)
    if (response.response && response.response.authenticatorData) {
      const authDataBytes = base64urlToUint8Array(response.response.authenticatorData);
      const flagsByte = authDataBytes[32]; // Byte index 32 contains flags
      decodedObj.authenticatorData_Flags = {
        UserPresence_UP: Boolean(flagsByte & 0x01),
        UserVerification_UV: Boolean(flagsByte & 0x04),
        AttestedCredentialData_AT: Boolean(flagsByte & 0x40),
        ExtensionData_ED: Boolean(flagsByte & 0x80),
        RawFlagsByte: `0b${flagsByte.toString(2).padStart(8, '0')}`
      };
      
      // Extract sign counter
      const view = new DataView(authDataBytes.buffer, authDataBytes.byteOffset, authDataBytes.byteLength);
      decodedObj.authenticatorData_SignCounter = view.getUint32(33, false); // Big endian 32-bit uint
    }

    decodedObj.ceremony = ceremonyType;
    decodedObj.verificationStatus = "Cryptographically Validated by Server";

    document.getElementById('json-decoded').innerText = JSON.stringify(decodedObj, null, 2);
  } catch (err) {
    document.getElementById('json-decoded').innerText = `Decoding Error: ${err.message}`;
  }
}

function clearInspectorLogs() {
  document.getElementById('json-options').innerText = '// Trigger a WebAuthn ceremony to view server options payload...';
  document.getElementById('json-response').innerText = '// Response from navigator.credentials.create() or get()...';
  document.getElementById('json-decoded').innerText = '// Decoded breakdown of clientDataJSON (Origin, Challenge) and authData flags...';
  updateStepper(0);
}

// Utility Functions
function showAlert(message, type = 'info') {
  const banner = document.getElementById('alert-banner');
  const msgEl = document.getElementById('alert-message');
  banner.className = `alert-banner ${type}`;
  msgEl.innerText = message;
  banner.classList.remove('hidden');
}

function hideAlert() {
  document.getElementById('alert-banner').classList.add('hidden');
}

function copyCode(elementId) {
  const code = document.getElementById(elementId).innerText;
  navigator.clipboard.writeText(code);
  showAlert('Copied JSON payload to clipboard!', 'info');
}

function escapeHtml(str) {
  return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function base64urlToBase64(base64url) {
  let base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
  while (base64.length % 4) base64 += '=';
  return base64;
}

function base64urlToUint8Array(base64url) {
  const base64 = base64urlToBase64(base64url);
  const raw = atob(base64);
  const array = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) {
    array[i] = raw.charCodeAt(i);
  }
  return array;
}
