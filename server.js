const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const { v4: uuidv4 } = require('uuid');
const bodyParser = require('body-parser');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(bodyParser.json());
// Serve the static frontend implicitly
app.use(express.static(__dirname));

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'finquest-app.html'));
});

const db = new sqlite3.Database(path.join(__dirname, 'finquest.db'), (err) => {
  if (err) console.error("Database opening error: ", err);
});

// Initialize DB schema
db.run(`CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT UNIQUE,
    password TEXT,
    data TEXT
)`);

db.run(`CREATE TABLE IF NOT EXISTS sessions (
    session_id TEXT PRIMARY KEY,
    user_id TEXT
)`);

app.post('/api/register', (req, res) => {
  const { email, password, defaultData } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Missing email or password' });
  
  const userId = uuidv4();
  const sessionToken = uuidv4();
  const stringifiedData = JSON.stringify(defaultData || {});

  db.run(`INSERT INTO users (id, email, password, data) VALUES (?, ?, ?, ?)`, [userId, email.toLowerCase(), password, stringifiedData], function(err) {
    if (err) {
      if (err.message.includes('UNIQUE')) return res.status(400).json({ error: 'Email already exists' });
      return res.status(500).json({ error: 'Internal error' });
    }
    
    db.run(`INSERT INTO sessions (session_id, user_id) VALUES (?, ?)`, [sessionToken, userId], (err) => {
      if (err) return res.status(500).json({ error: 'Session error' });
      res.json({ token: sessionToken, data: defaultData });
    });
  });
});

app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Missing email or password' });

  db.get(`SELECT id, data FROM users WHERE email = ? AND password = ?`, [email.toLowerCase(), password], (err, user) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (!user) return res.status(401).json({ error: 'Invalid email or password' });

    const sessionToken = uuidv4();
    db.run(`INSERT INTO sessions (session_id, user_id) VALUES (?, ?)`, [sessionToken, user.id], (err) => {
        if (err) return res.status(500).json({ error: 'Session error' });
        res.json({ token: sessionToken, data: JSON.parse(user.data) });
    });
  });
});

function auth(req, res, next) {
    const token = req.headers['authorization'];
    if (!token) return res.status(401).json({ error: 'No token' });
    
    db.get(`SELECT user_id FROM sessions WHERE session_id = ?`, [token], (err, session) => {
        if (err || !session) return res.status(401).json({ error: 'Invalid token' });
        req.userId = session.user_id;
        next();
    });
}

app.get('/api/me', auth, (req, res) => {
    db.get(`SELECT data FROM users WHERE id = ?`, [req.userId], (err, user) => {
        if (err || !user) return res.status(404).json({ error: 'User not found' });
        res.json({ data: JSON.parse(user.data) });
    });
});

app.post('/api/sync', auth, (req, res) => {
    const { data } = req.body;
    db.run(`UPDATE users SET data = ? WHERE id = ?`, [JSON.stringify(data), req.userId], function(err) {
        if (err) return res.status(500).json({ error: 'Save failed' });
        res.json({ success: true });
    });
});

app.listen(PORT, () => {
  console.log(`FinQuest backend running on http://localhost:${PORT}/finquest-app.html`);
});
