// server.js - Main backend server (Express + SQLite)
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const session = require('express-session');
const path = require('path');

const app = express();
const port = 3000;

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static('public'));
app.use(session({
    secret: 'your-secure-secret-key-change-in-production',
    resave: false,
    saveUninitialized: false,
    cookie: { 
        secure: false, // set true if using HTTPS
        httpOnly: true,
        maxAge: 30 * 60 * 1000 // 30 minutes
    }
}));

// Initialize SQLite database
const db = new sqlite3.Database('./users.db');

// Create users table with 2FA support
db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    twofa_secret TEXT,
    twofa_enabled INTEGER DEFAULT 0
)`);

// Helper: check if user is authenticated
function isAuthenticated(req, res, next) {
    if (req.session.userId) {
        next();
    } else {
        res.redirect('/login');
    }
}

// Routes
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/login', (req, res) => {
    if (req.session.userId) {
        return res.redirect('/dashboard');
    }
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/register', (req, res) => {
    if (req.session.userId) {
        return res.redirect('/dashboard');
    }
    res.sendFile(path.join(__dirname, 'public', 'register.html'));
});

app.get('/dashboard', isAuthenticated, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

// API: Register new user
app.post('/api/register', async (req, res) => {
    const { username, password } = req.body;

    // Input validation
    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password required' });
    }
    if (username.length < 3 || username.length > 20) {
        return res.status(400).json({ error: 'Username must be 3-20 characters' });
    }
    if (password.length < 6) {
        return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }
    if (!/^[a-zA-Z0-9_]+$/.test(username)) {
        return res.status(400).json({ error: 'Username can only contain letters, numbers, and underscores' });
    }

    try {
        // Hash password with bcrypt
        const hashedPassword = await bcrypt.hash(password, 10);
        
        db.run('INSERT INTO users (username, password) VALUES (?, ?)', 
            [username, hashedPassword], 
            function(err) {
                if (err) {
                    if (err.message.includes('UNIQUE')) {
                        return res.status(400).json({ error: 'Username already exists' });
                    }
                    return res.status(500).json({ error: 'Database error' });
                }
                res.json({ success: true, message: 'Registration successful! Please login.' });
            });
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

// API: Login
app.post('/api/login', (req, res) => {
    const { username, password, twofaToken } = req.body;
    
    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password required' });
    }
    // Use parameterized query to prevent SQL injection
    db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        if (!user) return res.status(401).json({ error: 'Invalid credentials' });
        
        // Verify password
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) return res.status(401).json({ error: 'Invalid credentials' });

        // Check 2FA if enabled
        if (user.twofa_enabled) {
            if (!twofaToken) {
                return res.status(200).json({ requiresTwoFactor: true, userId: user.id });
            }
            
            const verified = speakeasy.totp.verify({
                secret: user.twofa_secret,
                encoding: 'base32',
                token: twofaToken,
                window: 1
            });
            
            if (!verified) {
                return res.status(401).json({ error: 'Invalid 2FA code' });
            }
        }

        // Create session
        req.session.userId = user.id;
        req.session.username = user.username;
        
        res.json({ success: true, redirect: '/dashboard' });
    });
});

// API: Setup 2FA
app.post('/api/setup-2fa', isAuthenticated, (req, res) => {
    const userId = req.session.userId;
    
    // Generate secret for user
    const secret = speakeasy.generateSecret({ length: 20, name: `SecureApp:${req.session.username}` });
    
    db.run('UPDATE users SET twofa_secret = ? WHERE id = ?', [secret.base32, userId], (err) => {
        if (err) return res.status(500).json({ error: 'Failed to save 2FA secret' });
        
        // Generate QR code
        QRCode.toDataURL(secret.otpauth_url, (err, qrCodeUrl) => {
            if (err) return res.status(500).json({ error: 'Failed to generate QR code' });
            res.json({ secret: secret.base32, qrCode: qrCodeUrl });
        });
    });
});

// API: Verify and enable 2FA
app.post('/api/enable-2fa', isAuthenticated, (req, res) => {
    const { token } = req.body;
    const userId = req.session.userId;
    
    if (!token) return res.status(400).json({ error: 'Token required' });
    
    db.get('SELECT twofa_secret FROM users WHERE id = ?', [userId], (err, user) => {
        if (err || !user || !user.twofa_secret) {
            return res.status(500).json({ error: '2FA not setup' });
        }
        
        const verified = speakeasy.totp.verify({
            secret: user.twofa_secret,
            encoding: 'base32',
            token: token,
            window: 1
        });
        
        if (!verified) {
            return res.status(401).json({ error: 'Invalid verification code' });
        }
        
        db.run('UPDATE users SET twofa_enabled = 1 WHERE id = ?', [userId], (err) => {
            if (err) return res.status(500).json({ error: 'Failed to enable 2FA' });
            res.json({ success: true, message: '2FA enabled successfully!' });
        });
    });
});

// API: Disable 2FA
app.post('/api/disable-2fa', isAuthenticated, (req, res) => {
    const userId = req.session.userId;
    
    db.run('UPDATE users SET twofa_enabled = 0, twofa_secret = NULL WHERE id = ?', [userId], (err) => {
        if (err) return res.status(500).json({ error: 'Failed to disable 2FA' });
        res.json({ success: true, message: '2FA disabled' });
    });
});

// API: Get current user info
app.get('/api/user', isAuthenticated, (req, res) => {
    db.get('SELECT id, username, twofa_enabled FROM users WHERE id = ?', [req.session.userId], (err, user) => {
        if (err || !user) return res.status(500).json({ error: 'User not found' });
        res.json(user);
    });
});

// API: Logout
app.post('/api/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) return res.status(500).json({ error: 'Logout failed' });
        res.json({ success: true, redirect: '/login' });
    });
});
