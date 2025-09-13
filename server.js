const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const { open } = require('sqlite');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const fs = require('fs').promises;
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public'));
app.use('/uploads', express.static('uploads'));

// File upload configuration
const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, 'uploads/'),
    filename: (req, file, cb) => cb(null, `${Date.now()}-${Math.round(Math.random() * 1E9)}${path.extname(file.originalname)}`)
});
const upload = multer({ storage });

// Database connection
let db;

async function initDatabase() {
    try {
        db = await open({
            filename: './alucard.db',
            driver: sqlite3.Database
        });
        
        await db.exec('PRAGMA foreign_keys = ON');
        await db.exec('PRAGMA journal_mode = WAL');
        await db.exec('PRAGMA busy_timeout = 30000');
        
        await createTables();
        await migrateSchema();
        await insertSampleData();
        console.log('✅ Connected to SQLite database');
    } catch (error) {
        console.error('❌ Database connection failed:', error);
        throw error;
    }
}

async function createTables() {
    try {
        // Users table
        await db.exec(`
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL CHECK(length(username) >= 3 AND length(username) <= 20),
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                robux INTEGER DEFAULT 100 CHECK(robux >= 0),
                tix INTEGER DEFAULT 0 CHECK(tix >= 0),
                about_me TEXT,
                user_status TEXT DEFAULT 'Active',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_login DATETIME DEFAULT CURRENT_TIMESTAMP,
                avatar_data TEXT,
                is_active BOOLEAN DEFAULT TRUE,
                is_admin BOOLEAN DEFAULT FALSE,
                is_owner BOOLEAN DEFAULT FALSE,
                status TEXT CHECK(status IN ('pending', 'approved', 'denied', 'banned')) DEFAULT 'pending',
                application_reason TEXT,
                total_visits INTEGER DEFAULT 0 CHECK(total_visits >= 0),
                last_activity DATETIME DEFAULT CURRENT_TIMESTAMP,
                membership_type TEXT CHECK(membership_type IN ('None', 'BC', 'TBC', 'OBC')) DEFAULT 'None',
                membership_start DATETIME,
                last_daily_robux DATETIME,
                theme TEXT DEFAULT 'default',
                two_fa_enabled BOOLEAN DEFAULT FALSE,
                two_fa_secret TEXT,
                privacy_settings TEXT DEFAULT '{"messages":"Everyone","vip_invites":"Everyone","follow_game":"Everyone","inventory":"Everyone","trade":"Everyone","trade_quality":"None"}'
            )
        `);

        // Promocodes
        await db.exec(`
            CREATE TABLE IF NOT EXISTS promocodes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                code TEXT UNIQUE NOT NULL,
                robux_reward INTEGER DEFAULT 0,
                tix_reward INTEGER DEFAULT 0,
                max_uses INTEGER DEFAULT -1,
                current_uses INTEGER DEFAULT 0,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                expires_at DATETIME,
                is_active BOOLEAN DEFAULT TRUE
            )
        `);

        await db.exec(`
            CREATE TABLE IF NOT EXISTS user_promocodes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                promocode_id INTEGER NOT NULL,
                redeemed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (promocode_id) REFERENCES promocodes(id) ON DELETE CASCADE,
                UNIQUE(user_id, promocode_id)
            )
        `);

        // Currency exchanges
        await db.exec(`
            CREATE TABLE IF NOT EXISTS currency_exchanges (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                from_currency TEXT CHECK(from_currency IN ('robux', 'tix')) NOT NULL,
                to_currency TEXT CHECK(to_currency IN ('robux', 'tix')) NOT NULL,
                amount_from INTEGER NOT NULL,
                amount_to INTEGER NOT NULL,
                exchange_rate REAL NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        `);

        // Games
        await db.exec(`
            CREATE TABLE IF NOT EXISTS games (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL CHECK(length(title) >= 1),
                description TEXT,
                creator_id INTEGER NOT NULL,
                thumbnail_url TEXT,
                active_players INTEGER DEFAULT 0 CHECK(active_players >= 0),
                total_visits INTEGER DEFAULT 0 CHECK(total_visits >= 0),
                rating REAL DEFAULT 0.0 CHECK(rating >= 0.0 AND rating <= 5.0),
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                is_featured BOOLEAN DEFAULT FALSE,
                is_active BOOLEAN DEFAULT TRUE,
                category TEXT DEFAULT 'Adventure',
                FOREIGN KEY (creator_id) REFERENCES users(id) ON DELETE CASCADE
            )
        `);

        // Catalog items
        await db.exec(`
            CREATE TABLE IF NOT EXISTS catalog_items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL CHECK(length(name) >= 1),
                description TEXT,
                creator_id INTEGER NOT NULL,
                price INTEGER DEFAULT 0 CHECK(price >= 0),
                currency_type TEXT CHECK(currency_type IN ('free', 'robux', 'tix')) DEFAULT 'robux',
                item_type TEXT CHECK(item_type IN ('hat', 'hair', 'face', 'shirt', 'pants', 'accessory', 'gear', 'heads', 'faces', 'tshirts', 'torsos', 'l-arms', 'r-arms', 'l-legs', 'r-legs', 'packages')) NOT NULL,
                image_url TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                is_limited BOOLEAN DEFAULT FALSE,
                is_limited_u BOOLEAN DEFAULT FALSE,
                is_active BOOLEAN DEFAULT TRUE,
                is_pending BOOLEAN DEFAULT FALSE,
                stock_remaining INTEGER DEFAULT -1,
                sales_count INTEGER DEFAULT 0 CHECK(sales_count >= 0),
                FOREIGN KEY (creator_id) REFERENCES users(id) ON DELETE CASCADE
            )
        `);

        // User inventory
        await db.exec(`
            CREATE TABLE IF NOT EXISTS user_inventory (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                item_id INTEGER NOT NULL,
                purchased_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                is_equipped BOOLEAN DEFAULT FALSE,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (item_id) REFERENCES catalog_items(id) ON DELETE CASCADE,
                UNIQUE(user_id, item_id)
            )
        `);

        // Item sales for RAP
        await db.exec(`
            CREATE TABLE IF NOT EXISTS item_sales (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                item_id INTEGER NOT NULL,
                seller_id INTEGER NOT NULL,
                buyer_id INTEGER NOT NULL,
                price INTEGER NOT NULL,
                currency_type TEXT DEFAULT 'robux',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (item_id) REFERENCES catalog_items(id) ON DELETE CASCADE,
                FOREIGN KEY (seller_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (buyer_id) REFERENCES users(id) ON DELETE CASCADE
            )
        `);

        // Friends
        await db.exec(`
            CREATE TABLE IF NOT EXISTS friends (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                friend_id INTEGER NOT NULL,
                status TEXT CHECK(status IN ('pending', 'accepted', 'blocked', 'following')) DEFAULT 'pending',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (friend_id) REFERENCES users(id) ON DELETE CASCADE,
                UNIQUE(user_id, friend_id),
                CHECK(user_id != friend_id)
            )
        `);

        // Groups
        await db.exec(`
            CREATE TABLE IF NOT EXISTS groups (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL CHECK(length(name) >= 3 AND length(name) <= 50),
                description TEXT,
                creator_id INTEGER NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                member_count INTEGER DEFAULT 1 CHECK(member_count >= 0),
                is_active BOOLEAN DEFAULT TRUE,
                FOREIGN KEY (creator_id) REFERENCES users(id) ON DELETE CASCADE
            )
        `);

        await db.exec(`
            CREATE TABLE IF NOT EXISTS group_members (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                group_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                role TEXT CHECK(role IN ('member', 'admin', 'owner')) DEFAULT 'member',
                joined_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE CASCADE,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                UNIQUE(group_id, user_id)
            )
        `);

        // Admin logs
        await db.exec(`
            CREATE TABLE IF NOT EXISTS admin_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                admin_id INTEGER NOT NULL,
                action TEXT NOT NULL CHECK(length(action) >= 1),
                target_type TEXT,
                target_id INTEGER,
                details TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (admin_id) REFERENCES users(id) ON DELETE CASCADE
            )
        `);

        // Indexes
        await db.exec('CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)');
        await db.exec('CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)');
        await db.exec('CREATE INDEX IF NOT EXISTS idx_users_status ON users(status)');
        await db.exec('CREATE INDEX IF NOT EXISTS idx_games_creator ON games(creator_id)');
        await db.exec('CREATE INDEX IF NOT EXISTS idx_catalog_creator ON catalog_items(creator_id)');
        await db.exec('CREATE INDEX IF NOT EXISTS idx_catalog_type ON catalog_items(item_type)');
        await db.exec('CREATE INDEX IF NOT EXISTS idx_inventory_user ON user_inventory(user_id)');
        await db.exec('CREATE INDEX IF NOT EXISTS idx_friends_user ON friends(user_id)');
        await db.exec('CREATE INDEX IF NOT EXISTS idx_item_sales_item ON item_sales(item_id)');

        console.log('✅ Database tables created successfully');
    } catch (error) {
        console.error('❌ Error creating tables:', error);
        throw error;
    }
}

async function migrateSchema() {
    try {
        const columnsToAdd = [
            { table: 'users', column: 'avatar_data', type: 'TEXT' },
            { table: 'catalog_items', column: 'is_limited', type: 'BOOLEAN DEFAULT FALSE' },
            { table: 'catalog_items', column: 'is_limited_u', type: 'BOOLEAN DEFAULT FALSE' },
            { table: 'catalog_items', column: 'is_pending', type: 'BOOLEAN DEFAULT FALSE' },
            { table: 'users', column: 'status', type: 'TEXT CHECK(status IN ("pending", "approved", "denied", "banned")) DEFAULT "pending"' }
        ];

        for (const { table, column, type } of columnsToAdd) {
            try {
                const columnExists = await db.get('SELECT sql FROM sqlite_master WHERE type="table" AND name=? AND sql LIKE ?', [table, `%${column}%`]);
                if (!columnExists) {
                    await db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${type}`);
                    console.log(`✅ Added column ${column} to ${table}`);
                }
            } catch (error) {
                if (!error.message.includes('duplicate column name')) console.error(`Error adding column ${column} to ${table}:`, error.message);
            }
        }
    } catch (error) {
        console.error('❌ Migration error:', error);
    }
}

async function insertSampleData() {
    try {
        const userCount = await db.get('SELECT COUNT(*) as count FROM users');
        if (userCount.count > 0) return;

        const hashedPassword = await bcrypt.hash('thisrevivalisgoated', 10);
        
        await db.run('BEGIN TRANSACTION');
        
        try {
            const ownerResult = await db.run(`
                INSERT INTO users (username, email, password_hash, robux, tix, about_me, user_status, is_owner, is_admin, status) 
                VALUES ('ROBLOX', 'admin@alucard.com', ?, 999999, 999999, 'Creator @ Alucard', 'Active', 1, 1, 'approved')
            `, [hashedPassword]);

            const adminResult = await db.run(`
                INSERT INTO users (username, email, password_hash, robux, tix, about_me, user_status, is_admin, status) 
                VALUES ('yak', 'yak@alucard.com', ?, 999999, 999999, 'Creator @ Alucard', 'Active', 1, 'approved')
            `, [hashedPassword]);

            await db.run(`
                INSERT INTO promocodes (code, robux_reward, max_uses, is_active) 
                VALUES ('RELEASE', 100, -1, 1), ('ALUCARD', 100, -1, 1)
            `);

            // Sample catalog items
            await db.run(`
                INSERT INTO catalog_items (name, description, creator_id, price, item_type, image_url, is_limited) 
                VALUES 
                ('Cool Hat', 'A cool hat for your avatar', ?, 100, 'hat', 'https://tr.rbxcdn.com/asset/?id=123456', 1),
                ('Red Shirt', 'A red t-shirt', ?, 50, 'shirt', 'https://tr.rbxcdn.com/asset/?id=789012', 0),
                ('Blockhead', 'Classic Roblox head', ?, 0, 'heads', 'https://tr.rbxcdn.com/asset/?id=1', 0),
                ('Smile Face', 'A smiling face', ?, 25, 'faces', 'https://tr.rbxcdn.com/asset/?id=2', 0)
            `, [ownerResult.lastID, ownerResult.lastID, ownerResult.lastID, ownerResult.lastID]);

            // Groups
            const groups = [
                ['Alucard Official', 'A group for the original Alucard community members', ownerResult.lastID],
                ['Alucard Official FAN GROUP', 'Fans of the 2016 ROBLOX Revival', ownerResult.lastID],
                ['Alucard Moderation', 'for our moderation team', adminResult.lastID]
            ];

            for (const [name, description, creatorId] of groups) {
                const result = await db.run('INSERT INTO groups (name, description, creator_id) VALUES (?, ?, ?)', [name, description, creatorId]);
                await db.run('INSERT INTO group_members (group_id, user_id, role) VALUES (?, ?, "owner")', [result.lastID, creatorId]);
            }
            
            await db.run('COMMIT');
            console.log('✅ Sample data inserted successfully');
        } catch (error) {
            await db.run('ROLLBACK');
            throw error;
        }
    } catch (error) {
        console.error('❌ Error inserting sample data:', error);
    }
}

// Middleware
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Access token required' });
    jwt.verify(token, process.env.JWT_SECRET || 'alucard_secret_key', (err, user) => {
        if (err) return res.status(403).json({ error: 'Invalid token' });
        req.user = user;
        next();
    });
}

function requireAdmin(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Access token required' });
    jwt.verify(token, process.env.JWT_SECRET || 'alucard_secret_key', async (err, decoded) => {
        if (err) return res.status(403).json({ error: 'Invalid token' });
        try {
            if (!db) return res.status(500).json({ error: 'Database not available' });
            const user = await db.get('SELECT * FROM users WHERE id = ?', [decoded.userId]);
            if (!user || (!user.is_admin && !user.is_owner)) return res.status(403).json({ error: 'Admin access required' });
            req.user = decoded;
            req.userDetails = user;
            next();
        } catch (error) {
            console.error('Admin middleware error:', error);
            res.status(500).json({ error: 'Database error' });
        }
    });
}

async function logAdminAction(adminId, action, targetType = null, targetId = null, details = null) {
    try {
        await db.run('INSERT INTO admin_logs (admin_id, action, target_type, target_id, details) VALUES (?, ?, ?, ?, ?)', [adminId, action, targetType, targetId, details]);
    } catch (error) {
        console.error('Error logging admin action:', error);
    }
}

// Daily robux
async function distributeDailyRobux() {
    try {
        if (!db) return;
        const now = new Date();
        const yesterday = new Date(now.getTime() - 24 * 60 * 60 * 1000);
        const users = await db.all(`
            SELECT id, membership_type, last_daily_robux FROM users 
            WHERE membership_type != 'None' AND is_active = 1 AND status = 'approved' 
            AND (last_daily_robux IS NULL OR last_daily_robux < ?)
        `, [yesterday.toISOString()]);
        for (const user of users) {
            let dailyRobux = 0;
            switch (user.membership_type) {
                case 'BC': dailyRobux = 50; break;
                case 'TBC': dailyRobux = 125; break;
                case 'OBC': dailyRobux = 200; break;
            }
            if (dailyRobux > 0) {
                await db.run('UPDATE users SET robux = robux + ?, last_daily_robux = CURRENT_TIMESTAMP WHERE id = ?', [dailyRobux, user.id]);
            }
        }
        console.log(`✅ Distributed daily Robux to ${users.length} members`);
    } catch (error) {
        console.error('Error distributing daily Robux:', error);
    }
}

setInterval(distributeDailyRobux, 60 * 60 * 1000);

// Routes - Auth
app.post('/api/auth/register', async (req, res) => {
    try {
        const { username, email, password, applicationReason } = req.body;
        if (!username || !email || !password || !applicationReason) return res.status(400).json({ error: 'All fields are required' });
        if (username.length < 3 || username.length > 20) return res.status(400).json({ error: 'Username must be between 3 and 20 characters' });
        if (applicationReason.length < 10) return res.status(400).json({ error: 'Application reason must be at least 10 characters' });
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) return res.status(400).json({ error: 'Invalid email format' });
        if (!db) return res.status(500).json({ error: 'Database not available' });
        const existingUser = await db.get('SELECT id FROM users WHERE username = ? OR email = ?', [username, email]);
        if (existingUser) return res.status(400).json({ error: 'Username or email already exists' });
        const hashedPassword = await bcrypt.hash(password, 10);
        const result = await db.run('INSERT INTO users (username, email, password_hash, application_reason, status) VALUES (?, ?, ?, ?, "pending")', [username, email, hashedPassword, applicationReason]);
        res.status(201).json({ message: 'Application submitted successfully. Please wait for admin approval.', applicationId: result.lastID });
    } catch (error) {
        console.error('Registration error:', error);
        if (error.message.includes('UNIQUE constraint failed')) return res.status(400).json({ error: 'Username or email already exists' });
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        if (!username || !password) return res.status(400).json({ error: 'Username and password are required' });
        if (!db) return res.status(500).json({ error: 'Database not available' });
        const user = await db.get('SELECT * FROM users WHERE (username = ? OR email = ?) AND is_active = 1', [username, username]);
        if (!user) return res.status(400).json({ error: 'Invalid credentials' });
        if (user.status !== 'approved') return res.status(400).json({ error: 'Account not approved yet' });
        const validPassword = await bcrypt.compare(password, user.password_hash);
        if (!validPassword) return res.status(400).json({ error: 'Invalid credentials' });
        await db.run('UPDATE users SET last_login = CURRENT_TIMESTAMP, last_activity = CURRENT_TIMESTAMP WHERE id = ?', [user.id]);
        const token = jwt.sign({ userId: user.id, username: user.username }, process.env.JWT_SECRET || 'alucard_secret_key', { expiresIn: '24h' });
        res.json({
            message: 'Login successful',
            token,
            user: {
                id: user.id,
                username: user.username,
                about_me: user.about_me,
                user_status: user.user_status,
                robux: user.robux,
                tix: user.tix,
                email: user.email,
                is_admin: user.is_admin,
                is_owner: user.is_owner,
                status: user.status,
                membership_type: user.membership_type,
                theme: user.theme,
                avatar_data: user.avatar_data,
                badge: user.is_owner ? 'Owner' : user.is_admin ? 'Administrator' : 'Approved'
            }
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/api/auth/logout', authenticateToken, async (req, res) => {
    res.json({ message: 'Logged out successfully' });
});

// Currency exchange
app.post('/api/currency/exchange', authenticateToken, async (req, res) => {
    try {
        const { fromCurrency, toCurrency, amount } = req.body;
        const userId = req.user.userId;
        if (!['robux', 'tix'].includes(fromCurrency) || !['robux', 'tix'].includes(toCurrency)) return res.status(400).json({ error: 'Invalid currency type' });
        if (fromCurrency === toCurrency) return res.status(400).json({ error: 'Cannot exchange same currency' });
        const exchangeAmount = parseInt(amount);
        if (isNaN(exchangeAmount) || exchangeAmount <= 0) return res.status(400).json({ error: 'Invalid amount' });
        let convertedAmount;
        if (fromCurrency === 'tix' && toCurrency === 'robux') {
            if (exchangeAmount < 10) return res.status(400).json({ error: 'Minimum 10 Tix required to exchange for Robux' });
            convertedAmount = Math.floor(exchangeAmount / 10);
        } else if (fromCurrency === 'robux' && toCurrency === 'tix') {
            if (exchangeAmount < 1) return res.status(400).json({ error: 'Minimum 1 Robux required to exchange for Tix' });
            convertedAmount = exchangeAmount * 10;
        }
        if (!db) return res.status(500).json({ error: 'Database not available' });
        const user = await db.get('SELECT robux, tix FROM users WHERE id = ?', [userId]);
        if (!user) return res.status(404).json({ error: 'User not found' });
        const currentAmount = user[fromCurrency];
        if (currentAmount < exchangeAmount) return res.status(400).json({ error: `Insufficient ${fromCurrency}` });
        await db.run('BEGIN TRANSACTION');
        try {
            const updateQuery = `UPDATE users SET ${fromCurrency} = ${fromCurrency} - ?, ${toCurrency} = ${toCurrency} + ? WHERE id = ?`;
            await db.run(updateQuery, [exchangeAmount, convertedAmount, userId]);
            await db.run('INSERT INTO currency_exchanges (user_id, from_currency, to_currency, amount_from, amount_to, exchange_rate) VALUES (?, ?, ?, ?, ?, ?)', [userId, fromCurrency, toCurrency, exchangeAmount, convertedAmount, fromCurrency === 'robux' ? 10 : 0.1]);
            await db.run('COMMIT');
            const updatedUser = await db.get('SELECT robux, tix FROM users WHERE id = ?', [userId]);
            res.json({ message: 'Currency exchanged successfully', exchanged: { from: exchangeAmount, to: convertedAmount }, balance: { robux: updatedUser.robux, tix: updatedUser.tix } });
        } catch (error) {
            await db.run('ROLLBACK');
            throw error;
        }
    } catch (error) {
        console.error('Currency exchange error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Promocodes
app.post('/api/promocodes/redeem', authenticateToken, async (req, res) => {
    try {
        const { code } = req.body;
        const userId = req.user.userId;
        if (!code || typeof code !== 'string') return res.status(400).json({ error: 'Promocode is required' });
        if (!db) return res.status(500).json({ error: 'Database not available' });
        const promocode = await db.get('SELECT * FROM promocodes WHERE code = ? AND is_active = 1', [code.toUpperCase()]);
        if (!promocode) return res.status(404).json({ error: 'Invalid promocode' });
        if (promocode.expires_at && new Date(promocode.expires_at) < new Date()) return res.status(400).json({ error: 'Promocode has expired' });
        if (promocode.max_uses !== -1 && promocode.current_uses >= promocode.max_uses) return res.status(400).json({ error: 'Promocode has reached maximum uses' });
        const alreadyUsed = await db.get('SELECT id FROM user_promocodes WHERE user_id = ? AND promocode_id = ?', [userId, promocode.id]);
        if (alreadyUsed) return res.status(400).json({ error: 'You have already used this promocode' });
        await db.run('BEGIN TRANSACTION');
        try {
            if (promocode.robux_reward > 0) await db.run('UPDATE users SET robux = robux + ? WHERE id = ?', [promocode.robux_reward, userId]);
            if (promocode.tix_reward > 0) await db.run('UPDATE users SET tix = tix + ? WHERE id = ?', [promocode.tix_reward, userId]);
            await db.run('INSERT INTO user_promocodes (user_id, promocode_id) VALUES (?, ?)', [userId, promocode.id]);
            await db.run('UPDATE promocodes SET current_uses = current_uses + 1 WHERE id = ?', [promocode.id]);
            await db.run('COMMIT');
            const updatedUser = await db.get('SELECT robux, tix FROM users WHERE id = ?', [userId]);
            res.json({
                message: 'Promocode redeemed successfully!',
                rewards: { robux: promocode.robux_reward, tix: promocode.tix_reward },
                balance: { robux: updatedUser.robux, tix: updatedUser.tix }
            });
        } catch (error) {
            await db.run('ROLLBACK');
            throw error;
        }
    } catch (error) {
        console.error('Promocode redemption error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Membership
app.post('/api/membership/upgrade', authenticateToken, async (req, res) => {
    try {
        const { membershipType } = req.body;
        const userId = req.user.userId;
        if (!['BC', 'TBC', 'OBC'].includes(membershipType)) return res.status(400).json({ error: 'Invalid membership type' });
        if (!db) return res.status(500).json({ error: 'Database not available' });
        const user = await db.get('SELECT membership_type, robux FROM users WHERE id = ?', [userId]);
        if (!user) return res.status(404).json({ error: 'User not found' });
        if (user.membership_type === membershipType) return res.status(400).json({ error: 'You already have this membership type' });
        const membershipCosts = { BC: 100, TBC: 200, OBC: 500 };
        const cost = membershipCosts[membershipType];
        if (user.robux < cost) return res.status(400).json({ error: `Insufficient Robux. Need ${cost} Robux.` });
        await db.run('BEGIN TRANSACTION');
        try {
            await db.run('UPDATE users SET membership_type = ?, membership_start = CURRENT_TIMESTAMP, robux = robux - ? WHERE id = ?', [membershipType, cost, userId]);
            await db.run('COMMIT');
            res.json({ message: `Successfully upgraded to ${membershipType}!`, membershipType, cost, newBalance: user.robux - cost });
        } catch (error) {
            await db.run('ROLLBACK');
            throw error;
        }
    } catch (error) {
        console.error('Membership upgrade error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// User settings
app.get('/api/user/settings', authenticateToken, async (req, res) => {
    try {
        if (!db) return res.status(500).json({ error: 'Database not available' });
        const user = await db.get('SELECT username, email, theme, two_fa_enabled, privacy_settings, membership_type FROM users WHERE id = ?', [req.user.userId]);
        if (!user) return res.status(404).json({ error: 'User not found' });
        let privacySettings;
        try {
            privacySettings = JSON.parse(user.privacy_settings || '{}');
        } catch {
            privacySettings = { messages: "Everyone", vip_invites: "Everyone", follow_game: "Everyone", inventory: "Everyone", trade: "Everyone", trade_quality: "None" };
        }
        res.json({
            username: user.username,
            email: user.email,
            theme: user.theme,
            twoFactorEnabled: user.two_fa_enabled,
            membershipType: user.membership_type,
            privacy: privacySettings
        });
    } catch (error) {
        console.error('Get settings error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/api/user/settings/username', authenticateToken, async (req, res) => {
    try {
        const { newUsername, password } = req.body;
        const userId = req.user.userId;
        if (!newUsername || !password) return res.status(400).json({ error: 'Username and password are required' });
        if (newUsername.length < 3 || newUsername.length > 20) return res.status(400).json({ error: 'Username must be between 3 and 20 characters' });
        if (!db) return res.status(500).json({ error: 'Database not available' });
        const user = await db.get('SELECT password_hash, robux FROM users WHERE id = ?', [userId]);
        if (!user) return res.status(404).json({ error: 'User not found' });
        const validPassword = await bcrypt.compare(password, user.password_hash);
        if (!validPassword) return res.status(400).json({ error: 'Invalid password' });
        if (user.robux < 500) return res.status(400).json({ error: 'Insufficient Robux. Username change costs 500 Robux.' });
        const existingUser = await db.get('SELECT id FROM users WHERE username = ? AND id != ?', [newUsername, userId]);
        if (existingUser) return res.status(400).json({ error: 'Username already taken' });
        await db.run('BEGIN TRANSACTION');
        try {
            await db.run('UPDATE users SET username = ?, robux = robux - 500 WHERE id = ?', [newUsername, userId]);
            await db.run('COMMIT');
            res.json({ message: 'Username changed successfully!', newUsername, cost: 500, newBalance: user.robux - 500 });
        } catch (error) {
            await db.run('ROLLBACK');
            throw error;
        }
    } catch (error) {
        console.error('Username change error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/api/user/settings/password', authenticateToken, async (req, res) => {
    try {
        const { currentPassword, newPassword } = req.body;
        const userId = req.user.userId;
        if (!currentPassword || !newPassword) return res.status(400).json({ error: 'Current and new passwords are required' });
        if (newPassword.length < 6) return res.status(400).json({ error: 'New password must be at least 6 characters' });
        if (!db) return res.status(500).json({ error: 'Database not available' });
        const user = await db.get('SELECT password_hash FROM users WHERE id = ?', [userId]);
        if (!user) return res.status(404).json({ error: 'User not found' });
        const validPassword = await bcrypt.compare(currentPassword, user.password_hash);
        if (!validPassword) return res.status(400).json({ error: 'Current password is incorrect' });
        const hashedNewPassword = await bcrypt.hash(newPassword, 10);
        await db.run('UPDATE users SET password_hash = ? WHERE id = ?', [hashedNewPassword, userId]);
        res.json({ message: 'Password changed successfully!' });
    } catch (error) {
        console.error('Password change error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/api/user/settings/theme', authenticateToken, async (req, res) => {
    try {
        const { theme } = req.body;
        const userId = req.user.userId;
        if (!theme || !['default', 'dark', 'light'].includes(theme)) return res.status(400).json({ error: 'Invalid theme' });
        if (!db) return res.status(500).json({ error: 'Database not available' });
        await db.run('UPDATE users SET theme = ? WHERE id = ?', [theme, userId]);
        res.json({ message: 'Theme updated successfully!', theme });
    } catch (error) {
        console.error('Theme update error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/api/user/settings/privacy', authenticateToken, async (req, res) => {
    try {
        const { privacy } = req.body;
        const userId = req.user.userId;
        if (!privacy || typeof privacy !== 'object') return res.status(400).json({ error: 'Invalid privacy settings' });
        const validOptions = ['Everyone', 'Friends and Followers', 'Friends', 'No One'];
        const validSettings = ['messages', 'vip_invites', 'follow_game', 'inventory', 'trade'];
        for (const setting of validSettings) {
            if (privacy[setting] && !validOptions.includes(privacy[setting])) return res.status(400).json({ error: `Invalid value for ${setting}` });
        }
        if (!db) return res.status(500).json({ error: 'Database not available' });
        await db.run('UPDATE users SET privacy_settings = ? WHERE id = ?', [JSON.stringify(privacy), userId]);
        res.json({ message: 'Privacy settings updated successfully!' });
    } catch (error) {
        console.error('Privacy settings error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.get('/api/user/profile', authenticateToken, async (req, res) => {
    try {
        if (!db) return res.status(500).json({ error: 'Database not available' });
        const user = await db.get('SELECT id, username, email, about_me, user_status, robux, tix, created_at, last_login, is_admin, is_owner, status, membership_type, theme, avatar_data FROM users WHERE id = ?', [req.user.userId]);
        if (!user) return res.status(404).json({ error: 'User not found' });
        user.badge = user.is_owner ? 'Owner' : user.is_admin ? 'Administrator' : user.status === 'approved' ? 'Approved' : null;
        res.json(user);
    } catch (error) {
        console.error('Get profile error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Catalog
app.get('/api/catalog', async (req, res) => {
    try {
        const { type } = req.query;
        let query = 'SELECT ci.*, u.username as creator_username FROM catalog_items ci LEFT JOIN users u ON ci.creator_id = u.id WHERE is_active = 1 AND is_pending = 0';
        if (type) query += ` AND item_type = ?`;
        const items = await db.all(query, type ? [type] : []);
        res.json(items);
    } catch (error) {
        console.error('Catalog error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/api/catalog/buy', authenticateToken, async (req, res) => {
    try {
        const { itemId } = req.body;
        const userId = req.user.userId;
        if (!db) return res.status(500).json({ error: 'Database not available' });
        const item = await db.get('SELECT * FROM catalog_items WHERE id = ? AND is_active = 1 AND is_pending = 0', [itemId]);
        if (!item) return res.status(404).json({ error: 'Item not found' });
        const user = await db.get('SELECT robux, tix FROM users WHERE id = ?', [userId]);
        if (!user) return res.status(404).json({ error: 'User not found' });
        const balanceKey = item.currency_type === 'robux' ? 'robux' : 'tix';
        if (user[balanceKey] < item.price) return res.status(400).json({ error: `Insufficient ${balanceKey}` });
        const owned = await db.get('SELECT id FROM user_inventory WHERE user_id = ? AND item_id = ?', [userId, itemId]);
        if (owned && !item.is_limited && !item.is_limited_u) return res.status(400).json({ error: 'Already owned' });
        await db.run('BEGIN TRANSACTION');
        try {
            await db.run(`UPDATE users SET ${balanceKey} = ${balanceKey} - ? WHERE id = ?`, [item.price, userId]);
            await db.run('INSERT OR IGNORE INTO user_inventory (user_id, item_id, purchased_at) VALUES (?, ?, CURRENT_TIMESTAMP)', [userId, itemId]);
            if (item.stock_remaining > 0) await db.run('UPDATE catalog_items SET stock_remaining = stock_remaining - 1, sales_count = sales_count + 1 WHERE id = ?', [itemId]);
            if (item.is_limited || item.is_limited_u) {
                await db.run('INSERT INTO item_sales (item_id, seller_id, buyer_id, price, currency_type) VALUES (?, ?, ?, ?, ?)', [itemId, item.creator_id || 1, userId, item.price, item.currency_type]);
            }
            await db.run('COMMIT');
            res.json({ message: 'Purchased successfully!' });
        } catch (error) {
            await db.run('ROLLBACK');
            throw error;
        }
    } catch (error) {
        console.error('Buy item error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Friends
app.get('/api/friends', authenticateToken, async (req, res) => {
    try {
        if (!db) return res.status(500).json({ error: 'Database not available' });
        const friends = await db.all(`
            SELECT f.friend_id, u.username, f.status 
            FROM friends f 
            JOIN users u ON f.friend_id = u.id 
            WHERE f.user_id = ? AND f.status = 'accepted'
        `, [req.user.userId]);
        res.json(friends);
    } catch (error) {
        console.error('Friends error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Minigames - simplified
app.post('/api/minigames/play', authenticateToken, async (req, res) => {
    try {
        const { game, currency, amount } = req.body;
        const userId = req.user.userId;
        if (!db) return res.status(500).json({ error: 'Database not available' });
        const user = await db.get('SELECT robux, tix FROM users WHERE id = ?', [userId]);
        if (!user) return res.status(404).json({ error: 'User not found' });
        const balanceKey = currency;
        if (user[balanceKey] < amount) return res.status(400).json({ error: `Insufficient ${balanceKey}` });
        await db.run(`UPDATE users SET ${balanceKey} = ${balanceKey} - ? WHERE id = ?`, [amount, userId]);
        // For crash, return potential
        res.json({ message: 'Bet placed', payoutPotential: amount * 100 }); // Example
    } catch (error) {
        console.error('Minigame play error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/api/minigames/win', authenticateToken, async (req, res) => {
    try {
        const { game, winnings, currency } = req.body;
        const userId = req.user.userId;
        if (!db) return res.status(500).json({ error: 'Database not available' });
        await db.run(`UPDATE users SET ${currency} = ${currency} + ? WHERE id = ?`, [winnings, userId]);
        res.json({ message: 'Winnings added!' });
    } catch (error) {
        console.error('Minigame win error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// User Avatar Upload Route
app.post('/api/user/avatar', authenticateToken, async (req, res) => {
    try {
        upload.single('avatar')(req, res, async (err) => {
            if (err) return res.status(400).json({ error: 'Upload failed' });
            if (!req.file || !req.file.mimetype.startsWith('image/') || req.file.size > 2 * 1024 * 1024) {
                return res.status(400).json({ error: 'Invalid image: max 2MB' });
            }
            const imageUrl = `/uploads/${req.file.filename}`;
            const userId = req.user.userId;
            if (!db) return res.status(500).json({ error: 'Database not available' });
            await db.run('UPDATE users SET avatar_data = ? WHERE id = ?', [imageUrl, userId]);
            res.json({ message: 'Avatar updated!', avatarUrl: imageUrl });
        });
    } catch (error) {
        console.error('Avatar upload error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});
// Equip Item for Avatar Preview
app.post('/api/avatar/equip', authenticateToken, async (req, res) => {
    try {
        const { itemId } = req.body;
        const userId = req.user.userId;
        if (!db) return res.status(500).json({ error: 'Database not available' });
        const item = await db.get('SELECT image_url FROM catalog_items WHERE id = ? AND is_active = 1 AND is_pending = 0', [itemId]);
        if (!item) return res.status(404).json({ error: 'Item not found' });
        const inventory = await db.get('SELECT id FROM user_inventory WHERE user_id = ? AND item_id = ?', [userId, itemId]);
        if (!inventory) return res.status(400).json({ error: 'Item not owned' });
        // Simple preview: set avatar_data to item image (real app would composite multiple layers)
        await db.run('UPDATE users SET avatar_data = ? WHERE id = ?', [item.image_url, userId]);
        res.json({ message: 'Equipped! Preview updated.', avatarUrl: item.image_url });
    } catch (error) {
        console.error('Equip error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});
// Admin applications
app.get('/api/admin/applications', requireAdmin, async (req, res) => {
    try {
        const applications = await db.all('SELECT id, username, email, application_reason, created_at, status FROM users WHERE status = "pending" ORDER BY created_at ASC');
        res.json(applications);
    } catch (error) {
        console.error('Get applications error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/api/admin/applications/:id/approve', requireAdmin, async (req, res) => {
    try {
        const applicationId = req.params.id;
        const adminId = req.userDetails.id;
        const result = await db.run('UPDATE users SET status = "approved" WHERE id = ? AND status = "pending"', [applicationId]);
        if (result.changes === 0) return res.status(404).json({ error: 'Application not found or already processed' });
        await logAdminAction(adminId, 'APPROVE_APPLICATION', 'user', applicationId);
        res.json({ message: 'Application approved successfully' });
    } catch (error) {
        console.error('Approve application error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/api/admin/applications/:id/deny', requireAdmin, async (req, res) => {
    try {
        const applicationId = req.params.id;
        const adminId = req.userDetails.id;
        const result = await db.run('UPDATE users SET status = "denied" WHERE id = ? AND status = "pending"', [applicationId]);
        if (result.changes === 0) return res.status(404).json({ error: 'Application not found or already processed' });
        await logAdminAction(adminId, 'DENY_APPLICATION', 'user', applicationId);
        res.json({ message: 'Application denied successfully' });
    } catch (error) {
        console.error('Deny application error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Admin users ban
app.get('/api/admin/users', requireAdmin, async (req, res) => {
    try {
        const users = await db.all('SELECT id, username FROM users WHERE status != "banned" AND is_active = 1');
        res.json(users);
    } catch (error) {
        console.error('Get users error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/api/admin/users/:id/ban', requireAdmin, async (req, res) => {
    try {
        const userId = req.params.id;
        const adminId = req.userDetails.id;
        if (!req.userDetails.is_owner && userId == req.user.userId) return res.status(403).json({ error: 'Cannot ban self unless owner' });
        await db.run('UPDATE users SET status = "banned", is_active = FALSE WHERE id = ?', [userId]);
        await logAdminAction(adminId, 'BAN_USER', 'user', userId);
        res.json({ message: 'User banned successfully' });
    } catch (error) {
        console.error('Ban user error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Admin items
app.get('/api/admin/pending-items', requireAdmin, async (req, res) => {
    try {
        const items = await db.all('SELECT * FROM catalog_items WHERE is_pending = 1 ORDER BY created_at ASC');
        res.json(items);
    } catch (error) {
        console.error('Get pending items error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/api/admin/items/:id/approve', requireAdmin, async (req, res) => {
    try {
        const itemId = req.params.id;
        const adminId = req.userDetails.id;
        await db.run('UPDATE catalog_items SET is_pending = 0, is_active = 1 WHERE id = ?', [itemId]);
        await logAdminAction(adminId, 'APPROVE_ITEM', 'item', itemId);
        res.json({ message: 'Item approved successfully' });
    } catch (error) {
        console.error('Approve item error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/api/admin/items/:id/deny', requireAdmin, async (req, res) => {
    try {
        const itemId = req.params.id;
        const adminId = req.userDetails.id;
        await db.run('UPDATE catalog_items SET is_pending = 0, is_active = 0 WHERE id = ?', [itemId]);
        await logAdminAction(adminId, 'DENY_ITEM', 'item', itemId);
        res.json({ message: 'Item denied successfully' });
    } catch (error) {
        console.error('Deny item error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/api/admin/items', requireAdmin, async (req, res) => {
    try {
        upload.single('image')(req, res, async (err) => {
            if (err) return res.status(400).json({ error: 'Upload failed' });
            // Asset validation - simple
            if (!req.file || !req.file.mimetype.startsWith('image/') || req.file.size > 5 * 1024 * 1024) return res.status(400).json({ error: 'Invalid asset: image only, max 5MB' });
            const imageUrl = `/uploads/${req.file.filename}`;
            const { name, desc, price, type } = req.body;
            if (!name || !type) return res.status(400).json({ error: 'Name and type required' });
            const creatorId = req.userDetails.id;
            const result = await db.run(`
                INSERT INTO catalog_items (name, description, price, item_type, image_url, creator_id, is_pending) 
                VALUES (?, ?, ?, ?, ?, ?, 1)
            `, [name, desc || '', parseInt(price) || 0, type, imageUrl, creatorId]);
            await logAdminAction(creatorId, 'CREATE_ITEM', 'item', result.lastID, 'User-created item pending moderation');
            res.json({ message: 'Item created and pending moderation' });
        });
    } catch (error) {
        console.error('Create item error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Admin commands - owner only
app.post('/api/admin/command', requireAdmin, async (req, res) => {
    try {
        if (!req.userDetails.is_owner) return res.status(403).json({ error: 'Owner only for commands' });
        const { command } = req.body;
        if (!command) return res.status(400).json({ error: 'Command required' });
        // Simple /give @username amount currency
        if (command.startsWith('/give')) {
            const parts = command.split(' ');
            if (parts.length < 4) return res.status(400).json({ error: 'Invalid command format' });
            const targetUsername = parts[1].replace('@', '');
            const amount = parseInt(parts[2]);
            const currency = parts[3].toLowerCase();
            if (isNaN(amount) || !['robux', 'tix'].includes(currency)) return res.status(400).json({ error: 'Invalid amount or currency' });
            const targetUser = await db.get('SELECT id FROM users WHERE username = ?', [targetUsername]);
            if (!targetUser) return res.status(404).json({ error: 'User not found' });
            await db.run(`UPDATE users SET ${currency} = ${currency} + ? WHERE id = ?`, [amount, targetUser.id]);
            await logAdminAction(req.userDetails.id, 'GIVE_CURRENCY', 'user', targetUser.id, `${amount} ${currency} to ${targetUsername}`);
            res.json({ message: `Gave ${amount} ${currency} to ${targetUsername}` });
        } else {
            res.status(400).json({ error: 'Unknown command' });
        }
    } catch (error) {
        console.error('Command error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Placeholder
app.get('/api/placeholder/:width/:height', (req, res) => {
    const { width, height } = req.params;
    const text = req.query.text || 'Placeholder';
    const encodedText = encodeURIComponent(text);
    res.redirect(`https://via.placeholder.com/${width}x${height}/333333/ffffff?text=${encodedText}`);
});

app.get('/api/health', (req, res) => {
    res.json({ status: db ? 'healthy' : 'database_unavailable', timestamp: new Date().toISOString(), uptime: process.uptime() });
});

// Error handling
app.use((err, req, res, next) => {
    console.error('Unhandled error:', err);
    if (err.code === 'SQLITE_CONSTRAINT') return res.status(400).json({ error: 'Database constraint violation' });
    res.status(500).json({ error: 'Internal server error' });
});

app.use((req, res) => {
    res.status(404).json({ error: 'Endpoint not found' });
});

// Start server
async function startServer() {
    try {
        await initDatabase();
        distributeDailyRobux();
        const server = app.listen(PORT, () => {
            console.log('🚀 Alucard server running on port ' + PORT);
            console.log('Admin credentials: username "ROBLOX" or "yak", password "thisrevivalisgoated"');
        });
        process.on('SIGINT', async () => {
            console.log('\n🔄 Shutting down...');
            server.close(() => console.log('🔌 Server closed'));
            if (db) await db.close();
            process.exit(0);
        });
    } catch (error) {
        console.error('Failed to start server:', error);
        process.exit(1);
    }
}

startServer();

module.exports = app;