require('dotenv').config();
const express = require('express');
const expressWs = require('express-ws');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');

const app = express();
expressWs(app);

app.use(cors({ origin: '*' }));
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET || 'streetroots-secret-2024';

// ============================================================
// IN-MEMORY DATABASE (remplaçable par Supabase/PostgreSQL)
// ============================================================
const db = {
  users: [],         // { id, username, email, passwordHash, role, status, createdAt, inviteCode }
  invites: [],       // { code, createdBy, expiresAt, used }
  messages: [],      // { id, from, to, channel, content, type, createdAt }
  channels: [        // canaux par défaut
    { id: 'general', name: 'général', createdBy: 'system' },
    { id: 'design', name: 'design', createdBy: 'system' },
    { id: 'drops', name: 'drops', createdBy: 'system' },
  ],
  tasks: [],         // { id, title, description, assignedTo, createdBy, status, label, projectStep, createdAt, updatedAt }
  canvasData: {},    // { channelId: drawingData }
};

// Créer le compte fondateur par défaut
const initFounder = async () => {
  const hash = await bcrypt.hash('streetroots2024', 10);
  db.users.push({
    id: uuidv4(),
    username: 'fondateur',
    email: 'fondateur@streetroots.com',
    passwordHash: hash,
    role: 'founder',
    status: 'approved',
    createdAt: new Date().toISOString(),
  });
  console.log('✅ Compte fondateur créé — user: fondateur / pass: streetroots2024');
};
initFounder();

// ============================================================
// MIDDLEWARE AUTH
// ============================================================
const authMiddleware = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Non autorisé' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Token invalide' });
  }
};

const founderOnly = (req, res, next) => {
  if (req.user.role !== 'founder') return res.status(403).json({ error: 'Fondateur uniquement' });
  next();
};

// ============================================================
// AUTH ROUTES
// ============================================================

// Login
app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;
  const user = db.users.find(u => u.username === username || u.email === username);
  if (!user) return res.status(400).json({ error: 'Utilisateur introuvable' });
  if (user.status === 'pending') return res.status(403).json({ error: 'Compte en attente de validation par le fondateur' });
  if (user.status === 'suspended') return res.status(403).json({ error: 'Compte suspendu' });
  const valid = await bcrypt.compare(password, user.passwordHash);
  if (!valid) return res.status(400).json({ error: 'Mot de passe incorrect' });
  const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, user: { id: user.id, username: user.username, role: user.role, email: user.email } });
});

// Register via invite
app.post('/api/auth/register', async (req, res) => {
  const { username, email, password, inviteCode } = req.body;
  const invite = db.invites.find(i => i.code === inviteCode && !i.used && new Date(i.expiresAt) > new Date());
  if (!invite) return res.status(400).json({ error: 'Lien d\'invitation invalide ou expiré' });
  if (db.users.find(u => u.username === username)) return res.status(400).json({ error: 'Nom d\'utilisateur déjà pris' });
  if (db.users.find(u => u.email === email)) return res.status(400).json({ error: 'Email déjà utilisé' });
  const passwordHash = await bcrypt.hash(password, 10);
  const user = { id: uuidv4(), username, email, passwordHash, role: 'member', status: 'pending', createdAt: new Date().toISOString(), inviteCode };
  db.users.push(user);
  invite.used = true;
  res.json({ message: 'Compte créé. En attente de validation par le fondateur.' });
});

// Me
app.get('/api/auth/me', authMiddleware, (req, res) => {
  const user = db.users.find(u => u.id === req.user.id);
  res.json({ id: user.id, username: user.username, role: user.role, email: user.email });
});

// Status
app.get('/api/auth/status', authMiddleware, (req, res) => {
  const user = db.users.find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ error: 'Introuvable' });
  res.json({ status: user.status });
});

// ============================================================
// FOUNDER ROUTES
// ============================================================

// Générer un lien d'invitation
app.post('/api/founder/invite', authMiddleware, founderOnly, (req, res) => {
  const { expiresInHours = 48 } = req.body;
  const code = uuidv4().slice(0, 12).toUpperCase();
  const expiresAt = new Date(Date.now() + expiresInHours * 3600000).toISOString();
  db.invites.push({ code, createdBy: req.user.id, expiresAt, used: false, createdAt: new Date().toISOString() });
  res.json({ code, expiresAt, link: `/register?code=${code}` });
});

// Lister les comptes en attente
app.get('/api/founder/pending', authMiddleware, founderOnly, (req, res) => {
  res.json(db.users.filter(u => u.status === 'pending').map(u => ({ id: u.id, username: u.username, email: u.email, createdAt: u.createdAt })));
});

// Approuver un compte
app.post('/api/founder/approve/:id', authMiddleware, founderOnly, (req, res) => {
  const user = db.users.find(u => u.id === req.params.id);
  if (!user) return res.status(404).json({ error: 'Utilisateur introuvable' });
  user.status = 'approved';
  user.role = req.body.role || 'member';
  broadcastToAll({ type: 'USER_APPROVED', user: { id: user.id, username: user.username, role: user.role } });
  res.json({ message: 'Compte approuvé', user: { id: user.id, username: user.username, role: user.role } });
});

// Suspendre un compte
app.post('/api/founder/suspend/:id', authMiddleware, founderOnly, (req, res) => {
  const user = db.users.find(u => u.id === req.params.id);
  if (!user) return res.status(404).json({ error: 'Utilisateur introuvable' });
  user.status = 'suspended';
  res.json({ message: 'Compte suspendu' });
});

// Tous les membres
app.get('/api/founder/members', authMiddleware, founderOnly, (req, res) => {
  res.json(db.users.filter(u => u.role !== 'founder').map(u => ({ id: u.id, username: u.username, email: u.email, role: u.role, status: u.status })));
});

// ============================================================
// MESSAGING ROUTES
// ============================================================

app.get('/api/channels', authMiddleware, (req, res) => {
  res.json(db.channels);
});

app.post('/api/channels', authMiddleware, (req, res) => {
  const channel = { id: uuidv4(), name: req.body.name, createdBy: req.user.id, createdAt: new Date().toISOString() };
  db.channels.push(channel);
  broadcastToAll({ type: 'CHANNEL_CREATED', channel });
  res.json(channel);
});

app.get('/api/messages/:channelOrUserId', authMiddleware, (req, res) => {
  const id = req.params.channelOrUserId;
  const msgs = db.messages.filter(m =>
    m.channel === id ||
    (m.type === 'dm' && ((m.from === req.user.id && m.to === id) || (m.from === id && m.to === req.user.id)))
  ).slice(-100);
  res.json(msgs);
});

app.get('/api/users', authMiddleware, (req, res) => {
  res.json(db.users.filter(u => u.status === 'approved').map(u => ({ id: u.id, username: u.username, role: u.role })));
});

// ============================================================
// TASK ROUTES
// ============================================================

const LABELS = ['todo', 'en-cours', 'review', 'fait', 'bloqué'];
const STEPS = ['concept', 'croquis', 'validation', 'production', 'livré'];

app.get('/api/tasks', authMiddleware, (req, res) => {
  res.json(db.tasks);
});

app.post('/api/tasks', authMiddleware, (req, res) => {
  const { title, description, assignedTo, projectStep, label } = req.body;
  const task = {
    id: uuidv4(),
    title,
    description: description || '',
    assignedTo: assignedTo || null,
    createdBy: req.user.id,
    status: label || 'todo',
    projectStep: projectStep || 'concept',
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };
  db.tasks.push(task);
  broadcastToAll({ type: 'TASK_CREATED', task });
  res.json(task);
});

app.patch('/api/tasks/:id', authMiddleware, (req, res) => {
  const task = db.tasks.find(t => t.id === req.params.id);
  if (!task) return res.status(404).json({ error: 'Tâche introuvable' });
  Object.assign(task, req.body, { updatedAt: new Date().toISOString() });
  broadcastToAll({ type: 'TASK_UPDATED', task });
  res.json(task);
});

app.delete('/api/tasks/:id', authMiddleware, (req, res) => {
  const idx = db.tasks.findIndex(t => t.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Tâche introuvable' });
  db.tasks.splice(idx, 1);
  broadcastToAll({ type: 'TASK_DELETED', taskId: req.params.id });
  res.json({ message: 'Tâche supprimée' });
});

// ============================================================
// WEBSOCKET — Messagerie temps réel + Signaling vidéo
// ============================================================
const clients = new Map(); // userId -> ws

const broadcastToAll = (data) => {
  const msg = JSON.stringify(data);
  clients.forEach(ws => { try { ws.send(msg); } catch {} });
};

const sendTo = (userId, data) => {
  const ws = clients.get(userId);
  if (ws) try { ws.send(JSON.stringify(data)); } catch {}
};

app.ws('/ws', (ws, req) => {
  let userId = null;

  ws.on('message', (raw) => {
    let data;
    try { data = JSON.parse(raw); } catch { return; }

    switch (data.type) {

      case 'AUTH': {
        try {
          const decoded = jwt.verify(data.token, JWT_SECRET);
          userId = decoded.id;
          clients.set(userId, ws);
          ws.send(JSON.stringify({ type: 'AUTH_OK', userId }));
          broadcastToAll({ type: 'USER_ONLINE', userId, username: decoded.username });
        } catch {
          ws.send(JSON.stringify({ type: 'AUTH_ERROR' }));
        }
        break;
      }

      case 'MESSAGE': {
        if (!userId) return;
        const msg = {
          id: uuidv4(),
          from: userId,
          fromUsername: db.users.find(u => u.id === userId)?.username,
          to: data.to || null,
          channel: data.channel || null,
          content: data.content,
          type: data.to ? 'dm' : 'channel',
          createdAt: new Date().toISOString(),
        };
        db.messages.push(msg);
        if (msg.type === 'dm') {
          sendTo(data.to, { type: 'MESSAGE', message: msg });
          ws.send(JSON.stringify({ type: 'MESSAGE', message: msg }));
        } else {
          broadcastToAll({ type: 'MESSAGE', message: msg });
        }
        break;
      }

      // WebRTC Signaling pour la vidéo
      case 'VIDEO_OFFER':
      case 'VIDEO_ANSWER':
      case 'VIDEO_ICE':
      case 'VIDEO_CALL_REQUEST':
      case 'VIDEO_CALL_ACCEPT':
      case 'VIDEO_CALL_REJECT':
      case 'VIDEO_CALL_END': {
        if (!userId) return;
        const target = data.to;
        if (target) {
          sendTo(target, { ...data, from: userId, fromUsername: db.users.find(u => u.id === userId)?.username });
        } else {
          // broadcast (conférence groupe)
          clients.forEach((clientWs, clientId) => {
            if (clientId !== userId) {
              try { clientWs.send(JSON.stringify({ ...data, from: userId })); } catch {}
            }
          });
        }
        break;
      }

      case 'CANVAS_UPDATE': {
        if (!userId) return;
        broadcastToAll({ type: 'CANVAS_UPDATE', data: data.data, from: userId });
        break;
      }

      case 'VOTE': {
        if (!userId) return;
        broadcastToAll({ type: 'VOTE', targetId: data.targetId, vote: data.vote, from: userId, fromUsername: db.users.find(u => u.id === userId)?.username });
        break;
      }
    }
  });

  ws.on('close', () => {
    if (userId) {
      clients.delete(userId);
      broadcastToAll({ type: 'USER_OFFLINE', userId });
    }
  });
});

// Health check
app.get('/api/health', (req, res) => res.json({ status: 'ok', users: db.users.length, tasks: db.tasks.length }));

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => console.log(`🚀 streetRoots Backend sur http://localhost:${PORT}`));
