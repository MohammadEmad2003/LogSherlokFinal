/**
 * LogSherlock Authentication Module
 * Handles login, registration, password reset with OTP - Cookie-based
 */

const API_BASE = window.location.protocol === 'file:'
    ? 'http://localhost:8000'
    : window.location.origin;

// State
let currentForm = 'login';
let resetEmail = '';

// ============================================================================
// Form Navigation
// ============================================================================

function showForm(formName) {
    document.querySelectorAll('.auth-form').forEach(form => {
        form.classList.remove('active');
    });
    document.getElementById(`${formName}-form`).classList.add('active');
    currentForm = formName;
    hideMessage();
}

// ============================================================================
// Password Toggle
// ============================================================================

function togglePassword(inputId) {
    const input = document.getElementById(inputId);
    input.type = input.type === 'password' ? 'text' : 'password';
}

// ============================================================================
// Message Display
// ============================================================================

function showMessage(message, type = 'error') {
    const msgEl = document.getElementById('auth-message');
    msgEl.textContent = message;
    msgEl.className = `auth-message ${type}`;
    msgEl.style.display = 'block';

    if (type === 'success') {
        setTimeout(() => hideMessage(), 5000);
    }
}

function hideMessage() {
    document.getElementById('auth-message').style.display = 'none';
}

// ============================================================================
// Loading State
// ============================================================================

function setLoading(formId, loading) {
    const form = document.getElementById(formId);
    const btn = form.querySelector('.auth-btn');
    const btnText = btn.querySelector('.btn-text');
    const btnLoader = btn.querySelector('.btn-loader');

    btn.disabled = loading;
    btnText.style.display = loading ? 'none' : 'inline';
    btnLoader.style.display = loading ? 'flex' : 'none';
}

// ============================================================================
// Authentication Check
// ============================================================================

async function isAuthenticated() {
    try {
        const response = await fetch(`${API_BASE}/auth/me`, {
            credentials: 'include'
        });
        return response.ok;
    } catch {
        return false;
    }
}

// ============================================================================
// API Calls
// ============================================================================

async function apiCall(endpoint, method = 'GET', body = null) {
    const headers = {
        'Content-Type': 'application/json'
    };

    const options = {
        method,
        headers,
        credentials: 'include'  // Important for cookies
    };

    if (body) {
        options.body = JSON.stringify(body);
    }

    const response = await fetch(`${API_BASE}${endpoint}`, options);
    const data = await response.json();

    if (!response.ok) {
        throw new Error(data.detail || 'An error occurred');
    }

    return data;
}

// ===========================================================================
// Login
// ============================================================================

async function handleLogin(e) {
    e.preventDefault();
    hideMessage();
    setLoading('login-form-el', true);

    const email = document.getElementById('login-email').value;
    const password = document.getElementById('login-password').value;

    try {
        const data = await apiCall('/auth/login', 'POST', { email, password });
        showMessage('Login successful! Redirecting...', 'success');
        setTimeout(() => {
            window.location.href = 'index.html';
        }, 1000);
    } catch (error) {
        showMessage(error.message);
    } finally {
        setLoading('login-form-el', false);
    }
}

// ============================================================================
// Registration
// ============================================================================

async function handleRegister(e) {
    e.preventDefault();
    hideMessage();

    const fullName = document.getElementById('register-fullname').value;
    const username = document.getElementById('register-username').value;
    const email = document.getElementById('register-email').value;
    const password = document.getElementById('register-password').value;
    const confirm = document.getElementById('register-confirm').value;

    if (password !== confirm) {
        showMessage('Passwords do not match');
        return;
    }

    if (password.length < 6) {
        showMessage('Password must be at least 6 characters');
        return;
    }

    setLoading('register-form-el', true);

    try {
        const data = await apiCall('/auth/register', 'POST', {
            email,
            username,
            password,
            full_name: fullName
        });
        showMessage('Account created! Redirecting...', 'success');
        setTimeout(() => {
            window.location.href = 'index.html';
        }, 1000);
    } catch (error) {
        showMessage(error.message);
    } finally {
        setLoading('register-form-el', false);
    }
}

// ============================================================================
// Forgot Password
// ============================================================================

async function handleForgotPassword(e) {
    e.preventDefault();
    hideMessage();
    setLoading('forgot-form-el', true);

    const email = document.getElementById('forgot-email').value;
    resetEmail = email;

    try {
        await apiCall('/auth/forgot-password', 'POST', { email });
        showMessage('Reset code sent to your email!', 'success');
        setTimeout(() => {
            showForm('otp');
        }, 1500);
    } catch (error) {
        showMessage(error.message);
    } finally {
        setLoading('forgot-form-el', false);
    }
}

// ============================================================================
// OTP Verification & Password Reset
// ============================================================================

async function handleOTPSubmit(e) {
    e.preventDefault();
    hideMessage();

    const otpInputs = document.querySelectorAll('.otp-input');
    const otp = Array.from(otpInputs).map(input => input.value).join('');
    const newPassword = document.getElementById('new-password').value;

    if (otp.length !== 6) {
        showMessage('Please enter the complete 6-digit code');
        return;
    }

    if (newPassword.length < 6) {
        showMessage('Password must be at least 6 characters');
        return;
    }

    setLoading('otp-form-el', true);

    try {
        await apiCall('/auth/reset-password', 'POST', {
            email: resetEmail,
            otp,
            new_password: newPassword
        });
        showMessage('Password reset successful!', 'success');
        setTimeout(() => {
            showForm('login');
        }, 1500);
    } catch (error) {
        showMessage(error.message);
    } finally {
        setLoading('otp-form-el', false);
    }
}

function resendOTP() {
    if (resetEmail) {
        document.getElementById('forgot-email').value = resetEmail;
        showForm('forgot');
        document.getElementById('forgot-form-el').dispatchEvent(new Event('submit'));
    }
}

// ============================================================================
// OTP Input Handling
// ============================================================================

function setupOTPInputs() {
    const inputs = document.querySelectorAll('.otp-input');

    inputs.forEach((input, index) => {
        input.addEventListener('input', (e) => {
            const value = e.target.value;
            if (value.length === 1 && index < inputs.length - 1) {
                inputs[index + 1].focus();
            }
        });

        input.addEventListener('keydown', (e) => {
            if (e.key === 'Backspace' && !input.value && index > 0) {
                inputs[index - 1].focus();
            }
        });

        input.addEventListener('paste', (e) => {
            e.preventDefault();
            const pastedData = e.clipboardData.getData('text').slice(0, 6);
            pastedData.split('').forEach((char, i) => {
                if (inputs[i]) {
                    inputs[i].value = char;
                }
            });
            if (pastedData.length > 0) {
                inputs[Math.min(pastedData.length, inputs.length) - 1].focus();
            }
        });
    });
}

// ============================================================================
// Password Strength
// ============================================================================

function checkPasswordStrength(password) {
    let strength = 0;
    if (password.length >= 6) strength++;
    if (password.length >= 8) strength++;
    if (/[a-z]/.test(password) && /[A-Z]/.test(password)) strength++;
    if (/\d/.test(password)) strength++;
    if (/[^a-zA-Z\d]/.test(password)) strength++;

    const strengthEl = document.getElementById('password-strength');
    const levels = ['weak', 'fair', 'good', 'strong', 'excellent'];
    const colors = ['#ff4444', '#ffaa00', '#88cc00', '#00cc88', '#00ff88'];

    if (password.length === 0) {
        strengthEl.innerHTML = '';
        return;
    }

    const level = Math.min(strength, levels.length) - 1;
    strengthEl.innerHTML = `
        <div class="strength-bar">
            <div class="strength-fill" style="width: ${(strength / 5) * 100}%; background: ${colors[level]}"></div>
        </div>
        <span class="strength-text" style="color: ${colors[level]}">${levels[level]}</span>
    `;
}

// ============================================================================
// Initialization
// ============================================================================

document.addEventListener('DOMContentLoaded', async () => {
    // Check if already authenticated
    if (await isAuthenticated()) {
        window.location.href = 'index.html';
        return;
    }

    // Setup form listeners
    document.getElementById('login-form-el').addEventListener('submit', handleLogin);
    document.getElementById('register-form-el').addEventListener('submit', handleRegister);
    document.getElementById('forgot-form-el').addEventListener('submit', handleForgotPassword);
    document.getElementById('otp-form-el').addEventListener('submit', handleOTPSubmit);

    // Setup OTP inputs
    setupOTPInputs();

    // Setup password strength checker
    document.getElementById('register-password').addEventListener('input', (e) => {
        checkPasswordStrength(e.target.value);
    });

    // Check URL parameters for form type
    const urlParams = new URLSearchParams(window.location.search);
    const formParam = urlParams.get('form');
    if (formParam && ['login', 'register', 'forgot'].includes(formParam)) {
        showForm(formParam);
    }
});

// Export for use in other files
window.isAuthenticated = isAuthenticated;
window.showForm = showForm;
window.togglePassword = togglePassword;
window.resendOTP = resendOTP;
