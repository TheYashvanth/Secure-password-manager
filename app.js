// app.js
// State management
let currentUser = null;
let users = JSON.parse(localStorage.getItem('users')) || [];
let passwords = JSON.parse(localStorage.getItem('passwords')) || [];
let navigationHistory = []; // Track navigation history

// DOM Elements
const dom = {
    // Navigation
    navProfile: document.getElementById('nav-profile'),
    navDashboard: document.getElementById('nav-dashboard'),
    navAddPassword: document.getElementById('nav-add-password'),
    navViewPasswords: document.getElementById('nav-view-passwords'),
    navLogout: document.getElementById('nav-logout'),
    profileIcon: document.getElementById('profile-icon'),
    profileDropdown: document.getElementById('profile-dropdown'),
    
    // Pages
    profilePage: document.getElementById('profile-page'),
    loginPage: document.getElementById('login-page'),
    registerPage: document.getElementById('register-page'),
    setupMasterPage: document.getElementById('setup-master-page'),
    dashboardPage: document.getElementById('dashboard-page'),
    addPasswordPage: document.getElementById('add-password-page'),
    viewPasswordsPage: document.getElementById('view-passwords-page'),
    
    // Forms
    loginForm: document.getElementById('login-form'),
    registerForm: document.getElementById('register-form'),
    setupMasterForm: document.getElementById('setup-master-form'),
    addPasswordForm: document.getElementById('add-password-form'),
    
    // Inputs
    loginEmail: document.getElementById('login-email'),
    loginPassword: document.getElementById('login-password'),
    registerEmail: document.getElementById('register-email'),
    registerPassword: document.getElementById('register-password'),
    registerConfirmPassword: document.getElementById('register-confirm-password'),
    masterPassword: document.getElementById('master-password'),
    confirmMaster: document.getElementById('confirm-master'),
    masterStrength: document.getElementById('master-strength'),
    serviceName: document.getElementById('service-name'),
    username: document.getElementById('username'),
    password: document.getElementById('password'),
    
    // Other elements
    userEmail: document.getElementById('user-email'),
    profileEmail: document.getElementById('profile-email'),
    profileNotLoggedIn: document.getElementById('profile-not-logged-in'),
    profileLogin: document.getElementById('profile-login'),
    profileRegister: document.getElementById('profile-register'),
    passwordsTbody: document.getElementById('passwords-tbody'),
    noPasswordsMessage: document.getElementById('no-passwords-message'),
    alerts: document.getElementById('alerts'),
    showRegister: document.getElementById('show-register'),
    showLogin: document.getElementById('show-login'),
    goAddPassword: document.getElementById('go-add-password'),
    goViewPasswords: document.getElementById('go-view-passwords'),
    goAddPasswordFromView: document.getElementById('go-add-password-from-view'),
    backFromLogin: document.getElementById('back-from-login'),
    backFromRegister: document.getElementById('back-from-register'),
    backFromMaster: document.getElementById('back-from-master'),
    backFromDashboard: document.getElementById('back-from-dashboard'),
    backFromAddPassword: document.getElementById('back-from-add-password'),
    backFromViewPasswords: document.getElementById('back-from-view-passwords')
};

// Initialize the app
function init() {
    setupEventListeners();
    showPage('profile-page');
    updateNav();
}

function setupEventListeners() {
    // Navigation
    dom.navProfile.addEventListener('click', () => {
        showPage('profile-page');
        toggleDropdown(false);
    });
    dom.navDashboard.addEventListener('click', () => {
        showPage('dashboard-page');
        toggleDropdown(false);
    });
    dom.navAddPassword.addEventListener('click', () => {
        showPage('add-password-page');
        toggleDropdown(false);
    });
    dom.navViewPasswords.addEventListener('click', () => {
        showPage('view-passwords-page');
        toggleDropdown(false);
    });
    dom.navLogout.addEventListener('click', () => {
        handleLogout();
        toggleDropdown(false);
    });
    dom.profileIcon.addEventListener('click', () => toggleDropdown());
    
    // Form submissions
    dom.loginForm.addEventListener('submit', handleLogin);
    dom.registerForm.addEventListener('submit', handleRegister);
    dom.setupMasterForm.addEventListener('submit', handleMasterPasswordSetup);
    dom.addPasswordForm.addEventListener('submit', handleAddPassword);
    
    // Profile page buttons
    dom.profileLogin.addEventListener('click', () => showPage('login-page'));
    dom.profileRegister.addEventListener('click', () => showPage('register-page'));
    
    // Links
    dom.showRegister.addEventListener('click', () => showPage('register-page'));
    dom.showLogin.addEventListener('click', () => showPage('login-page'));
    
    // Buttons
    dom.goAddPassword.addEventListener('click', () => showPage('add-password-page'));
    dom.goViewPasswords.addEventListener('click', () => showPage('view-passwords-page'));
    dom.goAddPasswordFromView.addEventListener('click', () => showPage('add-password-page'));
    
    // Back buttons
    dom.backFromLogin.addEventListener('click', goBack);
    dom.backFromRegister.addEventListener('click', goBack);
    dom.backFromMaster.addEventListener('click', goBack);
    dom.backFromDashboard.addEventListener('click', goBack);
    dom.backFromAddPassword.addEventListener('click', goBack);
    dom.backFromViewPasswords.addEventListener('click', goBack);
    
    // Password strength check
    dom.masterPassword.addEventListener('input', checkPasswordStrength);
    
    // Close dropdown when clicking outside
    document.addEventListener('click', (e) => {
        if (!dom.profileIcon.contains(e.target) && !dom.profileDropdown.contains(e.target)) {
            toggleDropdown(false);
        }
    });
}

// Page management
function showPage(pageId) {
    // Push the current page to history before switching, unless it's the same page
    const currentPage = document.querySelector('.page[style*="block"]')?.id;
    if (currentPage && currentPage !== pageId && pageId !== 'profile-page') {
        navigationHistory.push(currentPage);
    }
    
    // Hide all pages and show the requested one
    document.querySelectorAll('.page').forEach(page => {
        page.style.display = 'none';
    });
    document.getElementById(pageId).style.display = 'block';
    
    if (pageId === 'dashboard-page') {
        dom.userEmail.textContent = currentUser ? currentUser.email : '';
    } else if (pageId === 'view-passwords-page') {
        loadPasswords();
    } else if (pageId === 'profile-page') {
        if (currentUser) {
            dom.profileEmail.textContent = currentUser.email;
            dom.profileNotLoggedIn.style.display = 'none';
            dom.profileLogin.style.display = 'none';
            dom.profileRegister.style.display = 'none';
        } else {
            dom.profileEmail.textContent = '';
            dom.profileNotLoggedIn.style.display = 'block';
            dom.profileLogin.style.display = 'inline-block';
            dom.profileRegister.style.display = 'inline-block';
        }
    }
    
    updateNav();
}

function goBack() {
    // Pop the last page from history and navigate to it
    const previousPage = navigationHistory.pop();
    if (previousPage) {
        showPage(previousPage);
    } else {
        // Default to profile-page if no history
        showPage('profile-page');
    }
}

function updateNav() {
    const isLoggedIn = currentUser !== null;
    
    dom.profileIcon.style.display = 'block';
    dom.profileDropdown.style.display = 'none';
    
    dom.navProfile.style.display = 'block';
    dom.navDashboard.style.display = isLoggedIn ? 'block' : 'none';
    dom.navAddPassword.style.display = isLoggedIn ? 'block' : 'none';
    dom.navViewPasswords.style.display = isLoggedIn ? 'block' : 'none';
    dom.navLogout.style.display = isLoggedIn ? 'block' : 'none';
}

function toggleDropdown(show) {
    dom.profileDropdown.style.display = show === undefined ? 
        (dom.profileDropdown.style.display === 'none' ? 'block' : 'none') : 
        (show ? 'block' : 'none');
}

// Auth functions
async function handleLogin(e) {
    e.preventDefault();
    const email = dom.loginEmail.value;
    const password = dom.loginPassword.value;
    
    try {
        const hashedPassword = await hashPassword(password);
        users = JSON.parse(localStorage.getItem('users')) || [];
        const user = users.find(u => u.email === email && u.password === hashedPassword);
        
        if (user) {
            currentUser = { ...user };
            showAlert('Login successful!', 'success');
            
            if (user.hasMasterPassword) {
                showPage('dashboard-page');
            } else {
                showPage('setup-master-page');
            }
        } else {
            showAlert('Invalid email or password', 'error');
        }
    } catch (error) {
        showAlert('Login failed. Please try again.', 'error');
        console.error('Login error:', error);
    }
}

async function handleRegister(e) {
    e.preventDefault();
    const email = dom.registerEmail.value;
    const password = dom.registerPassword.value;
    const confirmPassword = dom.registerConfirmPassword.value;
    
    if (password !== confirmPassword) {
        showAlert('Passwords do not match', 'error');
        return;
    }
    
    if (users.some(u => u.email === email)) {
        showAlert('Email already registered', 'error');
        return;
    }
    
    try {
        const hashedPassword = await hashPassword(password);
        const newUser = {
            id: Date.now(),
            email,
            password: hashedPassword,
            hasMasterPassword: false
        };
        
        users.push(newUser);
        localStorage.setItem('users', JSON.stringify(users));
        currentUser = { ...newUser };
        
        showAlert('Registration successful!', 'success');
        showPage('setup-master-page');
    } catch (error) {
        showAlert('Registration failed. Please try again.', 'error');
        console.error('Registration error:', error);
    }
}

async function handleMasterPasswordSetup(e) {
    e.preventDefault();
    const masterPassword = dom.masterPassword.value;
    const confirmMaster = dom.confirmMaster.value;
    
    if (masterPassword !== confirmMaster) {
        showAlert('Master passwords do not match', 'error');
        return;
    }
    
    if (!isStrongPassword(masterPassword)) {
        showAlert('Master password does not meet requirements', 'error');
        return;
    }
    
    try {
        const masterPasswordHash = await hashPassword(masterPassword);
        currentUser.masterPasswordHash = masterPasswordHash;
        currentUser.hasMasterPassword = true;
        
        users = users.map(u => u.id === currentUser.id ? { ...currentUser } : u);
        localStorage.setItem('users', JSON.stringify(users));
        
        showAlert('Master password set successfully!', 'success');
        showPage('dashboard-page');
    } catch (error) {
        showAlert('Failed to set master password', 'error');
        console.error('Master password setup error:', error);
    }
}

function handleLogout() {
    currentUser = null;
    navigationHistory = []; // Clear history on logout
    showAlert('Logged out successfully', 'success');
    showPage('profile-page');
    clearForms();
}

// Password management
async function handleAddPassword(e) {
    e.preventDefault();
    const service = dom.serviceName.value;
    const username = dom.username.value;
    const password = dom.password.value;
    
    try {
        const encryptedPassword = await encryptPassword(password, currentUser.masterPasswordHash);
        
        const newPassword = {
            id: Date.now(),
            userId: currentUser.id,
            service,
            username,
            password: encryptedPassword,
            createdAt: new Date().toISOString()
        };
        
        passwords.push(newPassword);
        localStorage.setItem('passwords', JSON.stringify(passwords));
        
        showAlert('Password saved successfully!', 'success');
        dom.addPasswordForm.reset();
        showPage('view-passwords-page');
    } catch (error) {
        showAlert('Failed to save password', 'error');
        console.error('Password save error:', error);
    }
}

function loadPasswords() {
    const userPasswords = passwords.filter(p => p.userId === currentUser.id);
    
    if (userPasswords.length === 0) {
        dom.noPasswordsMessage.style.display = 'block';
        dom.passwordsTbody.innerHTML = '';
        return;
    }
    
    dom.noPasswordsMessage.style.display = 'none';
    
    let html = '';
    userPasswords.forEach(pwd => {
        html += `
            <tr data-id="${pwd.id}">
                <td>${pwd.service}</td>
                <td>${pwd.username}</td>
                <td>
                    <span class="password-display" data-encrypted="${pwd.password}">********</span>
                    <span class="eye-icon" data-id="${pwd.id}" style="cursor: pointer;">👁️</span>
                </td>
                <td>
                    <button class="btn-decrypt" data-id="${pwd.id}">Decrypt</button>
                    <button class="btn-delete" data-id="${pwd.id}">Delete</button>
                </td>
            </tr>
        `;
    });
    
    dom.passwordsTbody.innerHTML = html;
    
    // Add event listeners to eye icons and buttons
    document.querySelectorAll('.eye-icon').forEach(icon => {
        icon.addEventListener('click', handleEyeIconClick);
    });
    
    document.querySelectorAll('.btn-decrypt').forEach(btn => {
        btn.addEventListener('click', (e) => {
            const id = parseInt(e.target.getAttribute('data-id'));
            showDecryptInput(id);
        });
    });
    
    document.querySelectorAll('.btn-delete').forEach(btn => {
        btn.addEventListener('click', (e) => {
            const id = parseInt(e.target.getAttribute('data-id'));
            deletePassword(id);
        });
    });
}

// Show an inline input for master password in the table row
function showDecryptInput(id) {
    const row = dom.passwordsTbody.querySelector(`tr[data-id="${id}"]`);
    const passwordCell = row.querySelector('td:nth-child(3)');
    
    // If already showing input, don't add another
    if (passwordCell.querySelector('.decrypt-input')) return;
    
    const input = document.createElement('input');
    input.type = 'password';
    input.className = 'decrypt-input';
    input.placeholder = 'Enter master password';
    
    const submitBtn = document.createElement('button');
    submitBtn.textContent = 'Submit';
    submitBtn.className = 'btn-decrypt';
    
    passwordCell.appendChild(input);
    passwordCell.appendChild(submitBtn);
    
    submitBtn.addEventListener('click', async () => {
        const masterPassword = input.value;
        if (!masterPassword) {
            showAlert('Master password is required', 'error');
            return;
        }
        
        try {
            const passwordObj = passwords.find(p => p.id === id);
            if (!passwordObj) {
                showAlert('Password not found', 'error');
                return;
            }
            
            const decryptedPassword = await decryptPassword(passwordObj.password, masterPassword);
            
            const passwordDisplay = row.querySelector('.password-display');
            passwordDisplay.dataset.decrypted = decryptedPassword;
            passwordDisplay.textContent = '********';
            
            // Remove input and submit button
            input.remove();
            submitBtn.remove();
            
            showAlert('Password decrypted successfully', 'success');
        } catch (error) {
            showAlert('Failed to decrypt password. Incorrect master password.', 'error');
            console.error('Decryption error:', error);
        }
    });
}

async function handleEyeIconClick(e) {
    const id = parseInt(e.target.getAttribute('data-id'));
    const row = e.target.closest('tr');
    const passwordDisplay = row.querySelector('.password-display');
    
    const passwordObj = passwords.find(p => p.id === id);
    if (!passwordObj) {
        showAlert('Password not found', 'error');
        return;
    }

    if (passwordDisplay.dataset.decrypted) {
        // Toggle between showing decrypted password and asterisks
        passwordDisplay.textContent = passwordDisplay.textContent === '********' ? 
            passwordDisplay.dataset.decrypted : '********';
    } else {
        // Show encrypted password if not yet decrypted
        passwordDisplay.textContent = passwordDisplay.textContent === '********' ? 
            passwordObj.password : '********';
    }
}

function deletePassword(id) {
    if (confirm('Are you sure you want to delete this password?')) {
        passwords = passwords.filter(p => p.id !== id);
        localStorage.setItem('passwords', JSON.stringify(passwords));
        loadPasswords();
        showAlert('Password deleted', 'success');
    }
}

// Security functions
async function hashPassword(password) {
    const encoder = new TextEncoder();
    const data = encoder.encode(password);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

async function encryptPassword(password, masterPasswordHash) {
    const encoder = new TextEncoder();
    
    const keyMaterial = await crypto.subtle.importKey(
        'raw',
        encoder.encode(masterPasswordHash),
        { name: 'PBKDF2' },
        false,
        ['deriveKey']
    );
    
    const salt = window.crypto.getRandomValues(new Uint8Array(16));
    const key = await crypto.subtle.deriveKey(
        {
            name: 'PBKDF2',
            salt: salt,
            iterations: 100000,
            hash: 'SHA-256'
        },
        keyMaterial,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
    );
    
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const encrypted = await crypto.subtle.encrypt(
        {
            name: 'AES-GCM',
            iv: iv
        },
        key,
        encoder.encode(password)
    );
    
    const combined = new Uint8Array(salt.length + iv.length + encrypted.byteLength);
    combined.set(salt, 0);
    combined.set(iv, salt.length);
    combined.set(new Uint8Array(encrypted), salt.length + iv.length);
    
    return btoa(String.fromCharCode.apply(null, combined));
}

async function decryptPassword(encrypted, masterPassword) {
    try {
        const hashedMasterPassword = await hashPassword(masterPassword);
        
        const decoder = new TextDecoder();
        const encryptedData = Uint8Array.from(atob(encrypted), c => c.charCodeAt(0));
        
        const salt = encryptedData.slice(0, 16);
        const iv = encryptedData.slice(16, 28);
        const ciphertext = encryptedData.slice(28);
        
        const encoder = new TextEncoder();
        const keyMaterial = await crypto.subtle.importKey(
            'raw',
            encoder.encode(hashedMasterPassword),
            { name: 'PBKDF2' },
            false,
            ['deriveKey']
        );
        
        const key = await crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt: salt,
                iterations: 100000,
                hash: 'SHA-256'
            },
            keyMaterial,
            { name: 'AES-GCM', length: 256 },
            false,
            ['decrypt']
        );
        
        const decrypted = await crypto.subtle.decrypt(
            {
                name: 'AES-GCM',
                iv: iv
            },
            key,
            ciphertext
        );
        
        return decoder.decode(decrypted);
    } catch (error) {
        console.error('Decryption failed:', error);
        throw new Error('Decryption failed - wrong master password?');
    }
}

// Password strength
function checkPasswordStrength() {
    const password = dom.masterPassword.value;
    let strength = 0;
    
    if (password.length >= 8) strength++;
    if (/[A-Z]/.test(password)) strength++;
    if (/[a-z]/.test(password)) strength++;
    if (/[0-9]/.test(password)) strength++;
    if (/[^A-Za-z0-9]/.test(password)) strength++;
    
    let strengthText = 'None';
    let strengthClass = '';
    
    if (password.length === 0) {
        strengthText = 'None';
    } else if (strength <= 2) {
        strengthText = 'Weak';
        strengthClass = 'strength-weak';
    } else if (strength === 3) {
        strengthText = 'Medium';
        strengthClass = 'strength-medium';
    } else {
        strengthText = 'Strong';
        strengthClass = 'strength-strong';
    }
    
    dom.masterStrength.textContent = strengthText;
    dom.masterStrength.className = 'password-strength ' + strengthClass;
}

function isStrongPassword(password) {
    return password.length >= 8 &&
           /[A-Z]/.test(password) &&
           /[a-z]/.test(password) &&
           /[0-9]/.test(password) &&
           /[^A-Za-z0-9]/.test(password);
}

// UI helpers
function showAlert(message, type) {
    const alert = document.createElement('div');
    alert.className = `alert alert-${type}`;
    alert.textContent = message;
    dom.alerts.appendChild(alert);
    
    setTimeout(() => {
        alert.remove();
    }, 5000);
}

function clearForms() {
    dom.loginForm.reset();
    dom.registerForm.reset();
    dom.setupMasterForm.reset();
    dom.addPasswordForm.reset();
}

// Initialize the app
window.addEventListener('DOMContentLoaded', init);