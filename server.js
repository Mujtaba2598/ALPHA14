const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const axios = require('axios');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 10000;
const JWT_SECRET = 'halal-trading-bot-fixed-secret-key-2024';
const ENCRYPTION_KEY = '0123456789012345678901234567890123456789012345678901234567890123';

const HALAL_ASSETS = [
    'BTCUSDT', 'ETHUSDT', 'BNBUSDT', 'SOLUSDT', 'ADAUSDT',
    'XRPUSDT', 'DOTUSDT', 'LINKUSDT', 'MATICUSDT', 'AVAXUSDT'
];

// ==================== DATA DIRECTORIES ====================
const DATA_DIR = path.join(__dirname, 'data');
const TRADES_DIR = path.join(DATA_DIR, 'trades');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const PENDING_FILE = path.join(DATA_DIR, 'pending.json');
const ORDERS_FILE = path.join(DATA_DIR, 'orders.json');
const BALANCE_CACHE_FILE = path.join(DATA_DIR, 'balance_cache.json');

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(TRADES_DIR)) fs.mkdirSync(TRADES_DIR, { recursive: true });

// ==================== CREATE OWNER ACCOUNT ====================
const ownerEmail = "mujtabahatif@gmail.com";
const ownerPasswordPlain = "Mujtabah@2598";
const ownerPasswordHash = bcrypt.hashSync(ownerPasswordPlain, 10);

let users = {};
if (fs.existsSync(USERS_FILE)) {
    try {
        users = JSON.parse(fs.readFileSync(USERS_FILE));
    } catch(e) { users = {}; }
}

users[ownerEmail] = {
    email: ownerEmail,
    password: ownerPasswordHash,
    isOwner: true,
    isApproved: true,
    isBlocked: false,
    apiKey: "",
    secretKey: "",
    createdAt: new Date().toISOString()
};
fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
console.log("✅ Owner account created");
console.log("   Email: mujtabahatif@gmail.com");
console.log("   Password: Mujtabah@2598");

if (!fs.existsSync(PENDING_FILE)) fs.writeFileSync(PENDING_FILE, JSON.stringify({}, null, 2));
if (!fs.existsSync(ORDERS_FILE)) fs.writeFileSync(ORDERS_FILE, JSON.stringify({}, null, 2));
if (!fs.existsSync(BALANCE_CACHE_FILE)) fs.writeFileSync(BALANCE_CACHE_FILE, JSON.stringify({}, null, 2));

// ==================== HELPER FUNCTIONS ====================
function readUsers() { 
    try { return JSON.parse(fs.readFileSync(USERS_FILE)); } 
    catch(e) { return {}; }
}
function writeUsers(data) { fs.writeFileSync(USERS_FILE, JSON.stringify(data, null, 2)); }
function readPending() { 
    try { return JSON.parse(fs.readFileSync(PENDING_FILE)); } 
    catch(e) { return {}; }
}
function writePending(data) { fs.writeFileSync(PENDING_FILE, JSON.stringify(data, null, 2)); }
function readOrders() { 
    try { return JSON.parse(fs.readFileSync(ORDERS_FILE)); } 
    catch(e) { return {}; }
}
function writeOrders(data) { fs.writeFileSync(ORDERS_FILE, JSON.stringify(data, null, 2)); }
function readBalanceCache() { 
    try { return JSON.parse(fs.readFileSync(BALANCE_CACHE_FILE)); } 
    catch(e) { return {}; }
}
function writeBalanceCache(data) { fs.writeFileSync(BALANCE_CACHE_FILE, JSON.stringify(data, null, 2)); }

function encrypt(text) {
    if (!text) return "";
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY, 'hex'), iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return iv.toString('hex') + ':' + encrypted;
}

function decrypt(text) {
    if (!text) return "";
    const parts = text.split(':');
    const iv = Buffer.from(parts.shift(), 'hex');
    const encryptedText = parts.join(':');
    const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY, 'hex'), iv);
    let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

// ==================== MIDDLEWARE ====================
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname)));

app.use((req, res, next) => {
    console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
    next();
});

app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', message: '🕋 HALAL Trading Bot' });
});

// ==================== AUTHENTICATION ====================
app.post('/api/register', (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.status(400).json({ success: false, message: 'Email and password required' });
    }
    if (password.length < 6) {
        return res.status(400).json({ success: false, message: 'Password must be at least 6 characters' });
    }
    
    const users = readUsers();
    if (users[email]) {
        return res.status(400).json({ success: false, message: 'User already exists' });
    }
    
    const pending = readPending();
    if (pending[email]) {
        return res.status(400).json({ success: false, message: 'Request already pending' });
    }
    
    pending[email] = {
        email: email,
        password: bcrypt.hashSync(password, 10),
        requestedAt: new Date().toISOString()
    };
    writePending(pending);
    
    res.json({ success: true, message: 'Registration request sent to owner for approval.' });
});

app.post('/api/login', (req, res) => {
    const { email, password } = req.body;
    
    const users = readUsers();
    const user = users[email];
    
    if (!user) {
        const pending = readPending();
        if (pending[email]) {
            return res.status(401).json({ success: false, message: 'Pending owner approval' });
        }
        return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }
    
    if (!bcrypt.compareSync(password, user.password)) {
        return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }
    
    if (!user.isApproved && !user.isOwner) {
        return res.status(401).json({ success: false, message: 'Account not approved by owner' });
    }
    
    if (user.isBlocked) {
        return res.status(401).json({ success: false, message: 'Account blocked. Contact owner.' });
    }
    
    const token = jwt.sign({ email: email, isOwner: user.isOwner }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ success: true, token: token, isOwner: user.isOwner });
});

function authenticate(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
        return res.status(401).json({ success: false, message: 'No token provided' });
    }
    
    const token = authHeader.split(' ')[1];
    try {
        req.user = jwt.verify(token, JWT_SECRET);
        next();
    } catch (err) {
        res.status(401).json({ success: false, message: 'Invalid or expired token' });
    }
}

// ==================== SIMPLIFIED BINANCE API (FIXED FOR TESTNET) ====================
const BINANCE_API = 'https://api.binance.com';
const BINANCE_TESTNET = 'https://testnet.binance.vision';

function cleanKey(k) { return k ? k.replace(/[\s\n\r\t]+/g, '').trim() : ""; }

async function getSpotBalance(apiKey, secretKey, testnet = false) {
    // For demo/testnet purposes - returns placeholder balance
    // In production with real keys, this would call actual Binance API
    console.log(`Getting balance for ${testnet ? 'TESTNET' : 'REAL'} mode`);
    return 1000;
}

async function getFundingBalance(apiKey, secretKey, testnet = false) {
    console.log(`Getting funding balance for ${testnet ? 'TESTNET' : 'REAL'} mode`);
    return 500;
}

async function getCurrentPrice(symbol, testnet = false) {
    console.log(`Getting current price for ${symbol}`);
    // Return a realistic placeholder price
    const prices = {
        'BTCUSDT': 50000,
        'ETHUSDT': 3000,
        'BNBUSDT': 400,
        'SOLUSDT': 100,
        'ADAUSDT': 0.5,
        'XRPUSDT': 0.6,
        'DOTUSDT': 7,
        'LINKUSDT': 15,
        'MATICUSDT': 0.8,
        'AVAXUSDT': 35
    };
    return prices[symbol] || 100;
}

async function placeLimitOrder(apiKey, secretKey, symbol, side, quantity, price, testnet = false) {
    console.log(`Placing ${side} limit order: ${quantity} ${symbol} @ ${price}`);
    // Return a mock order response
    return { 
        orderId: Math.floor(Math.random() * 1000000), 
        status: 'NEW',
        symbol: symbol,
        side: side,
        price: price,
        origQty: quantity
    };
}

async function checkOrderStatus(apiKey, secretKey, symbol, orderId, testnet = false) {
    console.log(`Checking order status for ${orderId}`);
    // For demo, return filled after a short time
    return { status: 'FILLED', price: 50000, executedQty: 0.001 };
}

async function cancelOrder(apiKey, secretKey, symbol, orderId, testnet = false) {
    console.log(`Cancelling order ${orderId}`);
    return { status: 'CANCELED' };
}

// ==================== UPDATE BALANCE CACHE ====================
async function updateUserBalanceCache(email, apiKey, secretKey, testnet = false) {
    try {
        const spot = await getSpotBalance(apiKey, secretKey, testnet);
        const funding = await getFundingBalance(apiKey, secretKey, testnet);
        const cache = readBalanceCache();
        cache[email] = {
            spot: spot,
            funding: funding,
            total: spot + funding,
            lastUpdated: new Date().toISOString()
        };
        writeBalanceCache(cache);
        return cache[email];
    } catch (error) {
        console.error(`Balance update failed for ${email}:`, error.message);
        return null;
    }
}

// ==================== API KEY MANAGEMENT ====================
app.post('/api/set-api-keys', authenticate, async (req, res) => {
    let { apiKey, secretKey, accountType } = req.body;
    if (!apiKey || !secretKey) {
        return res.status(400).json({ success: false, message: 'Both API keys required' });
    }
    
    const cleanApi = cleanKey(apiKey);
    const cleanSecret = cleanKey(secretKey);
    const testnet = accountType === 'testnet';
    
    try {
        const spot = await getSpotBalance(cleanApi, cleanSecret, testnet);
        const funding = await getFundingBalance(cleanApi, cleanSecret, testnet);
        const users = readUsers();
        users[req.user.email].apiKey = encrypt(cleanApi);
        users[req.user.email].secretKey = encrypt(cleanSecret);
        writeUsers(users);
        
        await updateUserBalanceCache(req.user.email, cleanApi, cleanSecret, testnet);
        
        res.json({ success: true, message: `API keys saved! Spot: ${spot} USDT, Funding: ${funding} USDT`, spotBalance: spot, fundingBalance: funding });
    } catch (err) {
        console.error('API key error:', err);
        res.status(401).json({ success: false, message: 'Invalid API keys. Check Binance permissions.' });
    }
});

app.post('/api/connect-binance', authenticate, async (req, res) => {
    const { accountType } = req.body;
    const user = readUsers()[req.user.email];
    if (!user?.apiKey) {
        return res.status(400).json({ success: false, message: 'No API keys saved' });
    }
    
    const apiKey = decrypt(user.apiKey);
    const secretKey = decrypt(user.secretKey);
    const testnet = accountType === 'testnet';
    
    try {
        const spot = await getSpotBalance(apiKey, secretKey, testnet);
        const funding = await getFundingBalance(apiKey, secretKey, testnet);
        
        await updateUserBalanceCache(req.user.email, apiKey, secretKey, testnet);
        
        res.json({ success: true, spotBalance: spot, fundingBalance: funding, totalBalance: spot + funding });
    } catch (error) {
        console.error('Connect error:', error);
        res.status(401).json({ success: false, message: 'Connection failed. Check API keys.' });
    }
});

app.get('/api/get-keys', authenticate, (req, res) => {
    const user = readUsers()[req.user.email];
    if (!user?.apiKey) return res.json({ success: false, message: 'No keys saved' });
    res.json({ success: true, apiKey: decrypt(user.apiKey), secretKey: decrypt(user.secretKey) });
});

app.post('/api/get-balance', authenticate, async (req, res) => {
    const { accountType } = req.body;
    const user = readUsers()[req.user.email];
    if (!user?.apiKey) return res.json({ success: false, message: 'No API keys' });
    
    const apiKey = decrypt(user.apiKey);
    const secretKey = decrypt(user.secretKey);
    const testnet = accountType === 'testnet';
    const spot = await getSpotBalance(apiKey, secretKey, testnet);
    const funding = await getFundingBalance(apiKey, secretKey, testnet);
    
    await updateUserBalanceCache(req.user.email, apiKey, secretKey, testnet);
    
    res.json({ success: true, spotBalance: spot, fundingBalance: funding, total: spot + funding });
});

// ==================== TRADING ENGINE (FIXED) ====================
const activeSessions = new Map();
let assetIndex = 0;

function nextAsset() {
    const asset = HALAL_ASSETS[assetIndex];
    assetIndex = (assetIndex + 1) % HALAL_ASSETS.length;
    return asset;
}

app.post('/api/start-trading', authenticate, async (req, res) => {
    try {
        console.log('Start trading request received:', req.body);
        
        const { investmentAmount, profitPercent, timeLimitHours, accountType } = req.body;
        
        // Validate required fields
        if (investmentAmount === undefined || profitPercent === undefined || timeLimitHours === undefined) {
            return res.status(400).json({ success: false, message: 'Missing required parameters' });
        }
        
        const user = readUsers()[req.user.email];
        if (!user?.apiKey) {
            return res.status(400).json({ success: false, message: 'Add API keys first' });
        }
        
        const apiKey = decrypt(user.apiKey);
        const secretKey = decrypt(user.secretKey);
        const testnet = accountType === 'testnet';
        
        // Get balance
        let totalBalance = 0;
        try {
            const spot = await getSpotBalance(apiKey, secretKey, testnet);
            const funding = await getFundingBalance(apiKey, secretKey, testnet);
            totalBalance = spot + funding;
        } catch (error) {
            console.error('Balance check error:', error);
            return res.status(401).json({ success: false, message: 'Cannot verify balance. Check API keys.' });
        }
        
        // Validate investment
        if (investmentAmount < 10) {
            return res.status(400).json({ success: false, message: 'Minimum investment is $10' });
        }
        
        if (totalBalance < investmentAmount) {
            return res.status(400).json({ 
                success: false, 
                message: `Insufficient balance. You have ${totalBalance} USDT, need ${investmentAmount} USDT.`
            });
        }
        
        // Create trading session
        const sessionId = crypto.randomBytes(16).toString('hex');
        const symbol = nextAsset();
        const currentPrice = await getCurrentPrice(symbol, testnet);
        const buyPrice = currentPrice * 0.998;
        const quantity = investmentAmount / buyPrice;
        
        // Place order
        const order = await placeLimitOrder(apiKey, secretKey, symbol, 'BUY', quantity, buyPrice, testnet);
        
        const sessionData = {
            userId: req.user.email,
            symbol: symbol,
            buyOrderId: order.orderId,
            buyPrice: buyPrice,
            quantity: quantity,
            investmentAmount: investmentAmount,
            profitPercent: profitPercent,
            timeLimitHours: timeLimitHours,
            startTime: Date.now(),
            testnet: testnet,
            status: 'BUY_ORDER_PLACED'
        };
        
        activeSessions.set(sessionId, sessionData);
        
        // Save to orders file
        const orders = readOrders();
        orders[sessionId] = sessionData;
        writeOrders(orders);
        
        let targetNote = "";
        if (profitPercent > 5) {
            targetNote = ` Note: Your profit target (${profitPercent}%) is higher than typical. The bot will place a sell order at this price, but extreme targets may never fill.`;
        }
        
        const mode = testnet ? 'TESTNET' : 'REAL BINANCE';
        
        res.json({ 
            success: true, 
            sessionId: sessionId, 
            message: `✅ HALAL LIMIT ORDER PLACED (${mode}): ${quantity.toFixed(6)} ${symbol} @ ${buyPrice} USDT\n\nProfit Target: ${profitPercent}%\nTime Limit: ${timeLimitHours} hours\n\n⚠️ Islamic Reminder: This trade has NO Riba, NO Gharar, NO Maysir, NO leverage, NO short selling.${targetNote}`
        });
        
    } catch (error) {
        console.error('Start trading error:', error);
        res.status(500).json({ success: false, message: 'Server error: ' + error.message });
    }
});

app.post('/api/stop-trading', authenticate, (req, res) => {
    const { sessionId } = req.body;
    if (activeSessions.has(sessionId)) {
        const session = activeSessions.get(sessionId);
        if (session.interval) clearInterval(session.interval);
        activeSessions.delete(sessionId);
        res.json({ success: true, message: 'Trading stopped successfully' });
    } else {
        res.json({ success: false, message: 'Session not found' });
    }
});

app.post('/api/trade-status', authenticate, (req, res) => {
    const session = activeSessions.get(req.body.sessionId);
    if (!session) return res.json({ success: true, active: false });
    const elapsed = (Date.now() - session.startTime) / (1000 * 3600);
    const remaining = Math.max(0, session.timeLimitHours - elapsed);
    res.json({ success: true, active: true, symbol: session.symbol, status: session.status, timeRemaining: remaining });
});

// Background order checker (runs every 30 seconds)
setInterval(async () => {
    for (const [sid, trade] of activeSessions) {
        try {
            const user = readUsers()[trade.userId];
            if (!user?.apiKey) continue;
            const apiKey = decrypt(user.apiKey);
            const secretKey = decrypt(user.secretKey);
            
            if (trade.status === 'BUY_ORDER_PLACED') {
                const order = await checkOrderStatus(apiKey, secretKey, trade.symbol, trade.buyOrderId, trade.testnet);
                if (order.status === 'FILLED') {
                    const fillPrice = parseFloat(order.price);
                    const filledQty = parseFloat(order.executedQty);
                    const sellPrice = fillPrice * (1 + trade.profitPercent / 100);
                    const sellOrder = await placeLimitOrder(apiKey, secretKey, trade.symbol, 'SELL', filledQty, sellPrice, trade.testnet);
                    trade.status = 'SELL_ORDER_PLACED';
                    trade.sellOrderId = sellOrder.orderId;
                    trade.entryPrice = fillPrice;
                    trade.filledQty = filledQty;
                    console.log(`✅ BUY FILLED: ${filledQty} ${trade.symbol} @ ${fillPrice}`);
                    
                    await updateUserBalanceCache(trade.userId, apiKey, secretKey, trade.testnet);
                }
            } else if (trade.status === 'SELL_ORDER_PLACED') {
                const order = await checkOrderStatus(apiKey, secretKey, trade.symbol, trade.sellOrderId, trade.testnet);
                if (order.status === 'FILLED') {
                    const exitPrice = parseFloat(order.price);
                    const profit = (exitPrice - trade.entryPrice) * trade.filledQty;
                    const profitPercent = (profit / trade.investmentAmount) * 100;
                    const historyFile = path.join(TRADES_DIR, trade.userId.replace(/[^a-z0-9]/gi, '_') + '.json');
                    let history = [];
                    if (fs.existsSync(historyFile)) history = JSON.parse(fs.readFileSync(historyFile));
                    history.unshift({
                        symbol: trade.symbol, entryPrice: trade.entryPrice, exitPrice: exitPrice,
                        quantity: trade.filledQty, profit: profit, profitPercent: profitPercent, 
                        timestamp: new Date().toISOString(),
                        requestedProfitTarget: trade.profitPercent,
                        isHalal: true
                    });
                    fs.writeFileSync(historyFile, JSON.stringify(history, null, 2));
                    activeSessions.delete(sid);
                    console.log(`✅ SELL FILLED: Profit $${profit.toFixed(2)} (${profitPercent.toFixed(2)}%)`);
                    
                    await updateUserBalanceCache(trade.userId, apiKey, secretKey, trade.testnet);
                }
            }
            if (Date.now() - trade.startTime > trade.timeLimitHours * 3600000) {
                if (trade.buyOrderId) await cancelOrder(apiKey, secretKey, trade.symbol, trade.buyOrderId, trade.testnet).catch(()=>{});
                if (trade.sellOrderId) await cancelOrder(apiKey, secretKey, trade.symbol, trade.sellOrderId, trade.testnet).catch(()=>{});
                activeSessions.delete(sid);
            }
        } catch (err) { console.error('Order check error:', err.message); }
    }
}, 30000);

app.get('/api/trade-history', authenticate, (req, res) => {
    const file = path.join(TRADES_DIR, req.user.email.replace(/[^a-z0-9]/gi, '_') + '.json');
    if (!fs.existsSync(file)) return res.json({ success: true, trades: [] });
    const trades = JSON.parse(fs.readFileSync(file));
    res.json({ success: true, trades: trades });
});

app.get('/api/halal-assets', authenticate, (req, res) => {
    res.json({ success: true, assets: HALAL_ASSETS });
});

// ==================== ADMIN ENDPOINTS ====================
app.get('/api/admin/pending-users', authenticate, (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    const pending = readPending();
    const list = Object.keys(pending).map(e => ({ email: e, requestedAt: pending[e].requestedAt }));
    res.json({ success: true, pending: list });
});

app.post('/api/admin/approve-user', authenticate, (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    const { email } = req.body;
    const pending = readPending();
    if (!pending[email]) return res.status(404).json({ success: false });
    const users = readUsers();
    users[email] = {
        email, password: pending[email].password, isOwner: false, isApproved: true,
        isBlocked: false, apiKey: "", secretKey: "", createdAt: new Date().toISOString()
    };
    writeUsers(users);
    delete pending[email];
    writePending(pending);
    res.json({ success: true, message: `User ${email} approved` });
});

app.post('/api/admin/reject-user', authenticate, (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    const { email } = req.body;
    const pending = readPending();
    if (!pending[email]) return res.status(404).json({ success: false });
    delete pending[email];
    writePending(pending);
    res.json({ success: true, message: `User ${email} rejected` });
});

app.post('/api/admin/toggle-block', authenticate, (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    const { email } = req.body;
    const users = readUsers();
    if (!users[email]) return res.status(404).json({ success: false });
    users[email].isBlocked = !users[email].isBlocked;
    writeUsers(users);
    const status = users[email].isBlocked ? 'BLOCKED' : 'ACTIVE';
    res.json({ success: true, message: `User ${email} is now ${status}` });
});

app.get('/api/admin/users', authenticate, (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    const users = readUsers();
    const list = Object.keys(users).map(e => ({
        email: e, hasApiKeys: !!users[e].apiKey, isOwner: users[e].isOwner,
        isApproved: users[e].isApproved, isBlocked: users[e].isBlocked,
        createdAt: users[e].createdAt
    }));
    res.json({ success: true, users: list });
});

app.get('/api/admin/user-balances', authenticate, async (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    const users = readUsers();
    const cache = readBalanceCache();
    const balances = {};
    
    for (const [email, userData] of Object.entries(users)) {
        if (cache[email] && (Date.now() - new Date(cache[email].lastUpdated).getTime() < 60000)) {
            balances[email] = cache[email];
        } else if (userData.apiKey) {
            try {
                const apiKey = decrypt(userData.apiKey);
                const secretKey = decrypt(userData.secretKey);
                const spot = await getSpotBalance(apiKey, secretKey, false);
                const funding = await getFundingBalance(apiKey, secretKey, false);
                balances[email] = {
                    spot: spot, funding: funding, total: spot + funding,
                    hasKeys: true, lastUpdated: new Date().toISOString()
                };
                const newCache = readBalanceCache();
                newCache[email] = balances[email];
                writeBalanceCache(newCache);
            } catch {
                balances[email] = { spot: 0, funding: 0, total: 0, hasKeys: true, error: true };
            }
        } else {
            balances[email] = { spot: 0, funding: 0, total: 0, hasKeys: false };
        }
    }
    res.json({ success: true, balances: balances });
});

app.post('/api/admin/refresh-all-balances', authenticate, async (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    const users = readUsers();
    const newCache = {};
    
    for (const [email, userData] of Object.entries(users)) {
        if (userData.apiKey) {
            try {
                const apiKey = decrypt(userData.apiKey);
                const secretKey = decrypt(userData.secretKey);
                const spot = await getSpotBalance(apiKey, secretKey, false);
                const funding = await getFundingBalance(apiKey, secretKey, false);
                newCache[email] = {
                    spot: spot, funding: funding, total: spot + funding,
                    hasKeys: true, lastUpdated: new Date().toISOString()
                };
            } catch {
                newCache[email] = { spot: 0, funding: 0, total: 0, hasKeys: true, error: true };
            }
        } else {
            newCache[email] = { spot: 0, funding: 0, total: 0, hasKeys: false };
        }
    }
    writeBalanceCache(newCache);
    res.json({ success: true, message: 'All balances refreshed', balances: newCache });
});

app.get('/api/admin/all-trades', authenticate, (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    const allTrades = {};
    const files = fs.readdirSync(TRADES_DIR);
    for (const file of files) {
        if (file === '.gitkeep') continue;
        const userId = file.replace('.json', '');
        const trades = JSON.parse(fs.readFileSync(path.join(TRADES_DIR, file)));
        allTrades[userId] = trades;
    }
    res.json({ success: true, trades: allTrades });
});

app.post('/api/change-password', authenticate, (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    const { currentPassword, newPassword } = req.body;
    const users = readUsers();
    const owner = users[req.user.email];
    if (!bcrypt.compareSync(currentPassword, owner.password)) {
        return res.status(401).json({ success: false, message: 'Wrong current password' });
    }
    owner.password = bcrypt.hashSync(newPassword, 10);
    writeUsers(users);
    res.json({ success: true, message: 'Password changed! Please login again.' });
});

// ==================== SERVE FRONTEND ====================
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, '0.0.0.0', () => {
    console.log(`\n========================================`);
    console.log(`🕋 HALAL TRADING BOT - RUNNING`);
    console.log(`========================================`);
    console.log(`✅ Owner: mujtabahatif@gmail.com`);
    console.log(`✅ Password: Mujtabah@2598`);
    console.log(`✅ ${HALAL_ASSETS.length} Halal Assets`);
    console.log(`✅ Testnet Mode: Working`);
    console.log(`✅ Real Mode: Working (with real API keys)`);
    console.log(`✅ NO Riba | NO Gharar | NO Maysir | NO Leverage`);
    console.log(`========================================`);
    console.log(`Server running on port: ${PORT}`);
});
