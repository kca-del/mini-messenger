// server.js — Express + Socket.IO + JWT + SQLite + WebRTC-сигнализация
const path = require('path');
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const db = require('./db');

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'change-me-in-production-please-32-chars-min';

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' } });

app.use(express.json({ limit: '1mb' }));
app.use(express.static(path.join(__dirname, 'public')));

/* ============================================================
   УТИЛИТЫ
============================================================ */
const COLORS = ['#7C5CFF','#00D9FF','#FF4D9D','#F5C842','#4ADE80','#FF6B6B','#A855F7','#14B8A6'];

function pickColor() {
  return COLORS[Math.floor(Math.random() * COLORS.length)];
}

function now() { return Date.now(); }

function sanitize(str, max = 4000) {
  if (typeof str !== 'string') return '';
  return str.replace(/\s+/g, ' ').trim().slice(0, max);
}

function issueToken(user) {
  return jwt.sign(
    { uid: user.id, username: user.username },
    JWT_SECRET,
    { expiresIn: '30d' }
  );
}

function verifyToken(token) {
  try { return jwt.verify(token, JWT_SECRET); }
  catch { return null; }
}

function publicUser(u) {
  return {
    id: u.id,
    username: u.username,
    displayName: u.display_name,
    color: u.color,
    lastSeen: u.last_seen
  };
}

/* ============================================================
   HTTP API
============================================================ */

// Регистрация
app.post('/api/register', async (req, res) => {
  try {
    const username = String(req.body.username || '').trim().toLowerCase();
    const displayName = sanitize(req.body.displayName || username, 40);
    const password = String(req.body.password || '');

    if (!/^[a-z0-9_]{3,20}$/.test(username)) {
      return res.status(400).json({ error: 'Логин: 3–20 символов, латиница, цифры, _' });
    }
    if (password.length < 4) {
      return res.status(400).json({ error: 'Пароль минимум 4 символа' });
    }
    if (!displayName) {
      return res.status(400).json({ error: 'Введите отображаемое имя' });
    }

    const existing = db.prepare('SELECT id FROM users WHERE username = ?').get(username);
    if (existing) return res.status(409).json({ error: 'Логин уже занят' });

    const hash = await bcrypt.hash(password, 10);
    const ts = now();

    const info = db.prepare(`
      INSERT INTO users (username, display_name, password_hash, color, created_at, last_seen)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(username, displayName, hash, pickColor(), ts, ts);

    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(info.lastInsertRowid);
    const token = issueToken(user);
    res.json({ token, user: publicUser(user) });
  } catch (e) {
    console.error('register error', e);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// Вход
app.post('/api/login', async (req, res) => {
  try {
    const username = String(req.body.username || '').trim().toLowerCase();
    const password = String(req.body.password || '');

    const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
    if (!user) return res.status(401).json({ error: 'Неверный логин или пароль' });

    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: 'Неверный логин или пароль' });

    db.prepare('UPDATE users SET last_seen = ? WHERE id = ?').run(now(), user.id);

    const token = issueToken(user);
    res.json({ token, user: publicUser(user) });
  } catch (e) {
    console.error('login error', e);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// Middleware авторизации для API
function auth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  const payload = token ? verifyToken(token) : null;
  if (!payload) return res.status(401).json({ error: 'Не авторизован' });
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(payload.uid);
  if (!user) return res.status(401).json({ error: 'Пользователь не найден' });
  req.user = user;
  next();
}

// Текущий пользователь
app.get('/api/me', auth, (req, res) => {
  res.json({ user: publicUser(req.user) });
});

// Список всех пользователей
app.get('/api/users', auth, (req, res) => {
  const users = db.prepare(`
    SELECT id, username, display_name, color, last_seen
    FROM users
    WHERE id != ?
    ORDER BY display_name COLLATE NOCASE
  `).all(req.user.id);
  res.json({ users: users.map(u => ({
    id: u.id,
    username: u.username,
    displayName: u.display_name,
    color: u.color,
    lastSeen: u.last_seen
  })) });
});

// История переписки
app.get('/api/messages/:userId', auth, (req, res) => {
  const otherId = Number(req.params.userId);
  if (!Number.isInteger(otherId)) return res.status(400).json({ error: 'Некорректный id' });

  const rows = db.prepare(`
    SELECT id, from_id AS fromId, to_id AS toId, text, created_at AS createdAt, read_at AS readAt
    FROM messages
    WHERE (from_id = ? AND to_id = ?) OR (from_id = ? AND to_id = ?)
    ORDER BY created_at ASC
    LIMIT 500
  `).all(req.user.id, otherId, otherId, req.user.id);

  // Помечаем прочитанными
  db.prepare(`
    UPDATE messages SET read_at = ?
    WHERE from_id = ? AND to_id = ? AND read_at IS NULL
  `).run(now(), otherId, req.user.id);

  res.json({ messages: rows });
});

/* ============================================================
   SOCKET.IO
============================================================ */
const online = new Map(); // userId -> socketId

io.use((socket, next) => {
  const token = socket.handshake.auth && socket.handshake.auth.token;
  const payload = token ? verifyToken(token) : null;
  if (!payload) return next(new Error('unauthorized'));

  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(payload.uid);
  if (!user) return next(new Error('unauthorized'));

  socket.data.user = publicUser(user);
  next();
});

function broadcastOnline() {
  const list = [...online.keys()];
  io.emit('online:list', list);
}

io.on('connection', (socket) => {
  const me = socket.data.user;

  // Регистрируем
  online.set(me.id, socket.id);
  db.prepare('UPDATE users SET last_seen = ? WHERE id = ?').run(now(), me.id);
  broadcastOnline();
  socket.broadcast.emit('user:online', { id: me.id });

  /* ---------- СООБЩЕНИЯ ---------- */
  socket.on('message:send', (payload, ack) => {
    try {
      const toId = Number(payload && payload.to);
      const text = sanitize(payload && payload.text, 4000);

      if (!Number.isInteger(toId)) return ack && ack({ error: 'Некорректный получатель' });
      if (!text) return ack && ack({ error: 'Пустое сообщение' });

      const toUser = db.prepare('SELECT id FROM users WHERE id = ?').get(toId);
      if (!toUser) return ack && ack({ error: 'Пользователь не найден' });

      const ts = now();
      const info = db.prepare(`
        INSERT INTO messages (from_id, to_id, text, created_at)
        VALUES (?, ?, ?, ?)
      `).run(me.id, toId, text, ts);

      const msg = {
        id: info.lastInsertRowid,
        fromId: me.id,
        toId,
        text,
        createdAt: ts,
        readAt: null
      };

      // Отдаём получателю если онлайн
      const toSocket = online.get(toId);
      if (toSocket) {
        io.to(toSocket).emit('message:new', msg);
      }
      // И себе (подтверждение)
      socket.emit('message:new', msg);

      ack && ack({ ok: true, message: msg });
    } catch (e) {
      console.error('message:send', e);
      ack && ack({ error: 'Ошибка сервера' });
    }
  });

  socket.on('message:read', (payload) => {
    const fromId = Number(payload && payload.from);
    if (!Number.isInteger(fromId)) return;
    db.prepare(`
      UPDATE messages SET read_at = ?
      WHERE from_id = ? AND to_id = ? AND read_at IS NULL
    `).run(now(), fromId, me.id);

    const fromSocket = online.get(fromId);
    if (fromSocket) {
      io.to(fromSocket).emit('message:read', { by: me.id });
    }
  });

  /* ---------- ИНДИКАТОР "ПЕЧАТАЕТ" ---------- */
  socket.on('typing', (payload) => {
    const toId = Number(payload && payload.to);
    const isTyping = !!(payload && payload.isTyping);
    if (!Number.isInteger(toId)) return;
    const toSocket = online.get(toId);
    if (toSocket) {
      io.to(toSocket).emit('typing', { from: me.id, isTyping });
    }
  });

  /* ---------- WEBRTC СИГНАЛИЗАЦИЯ ---------- */
  socket.on('call:invite', (payload) => {
    const toId = Number(payload && payload.to);
    const video = !!(payload && payload.video);
    if (!Number.isInteger(toId)) return;
    const toSocket = online.get(toId);
    if (!toSocket) {
      socket.emit('call:unavailable', { to: toId });
      return;
    }
    io.to(toSocket).emit('call:incoming', {
      from: me.id,
      fromUser: me,
      video
    });
  });

  socket.on('call:accept', (payload) => {
    const toId = Number(payload && payload.to);
    if (!Number.isInteger(toId)) return;
    const toSocket = online.get(toId);
    if (toSocket) {
      io.to(toSocket).emit('call:accepted', { from: me.id });
    }
  });

  socket.on('call:reject', (payload) => {
    const toId = Number(payload && payload.to);
    if (!Number.isInteger(toId)) return;
    const toSocket = online.get(toId);
    if (toSocket) {
      io.to(toSocket).emit('call:rejected', { from: me.id });
    }
  });

  socket.on('call:end', (payload) => {
    const toId = Number(payload && payload.to);
    if (!Number.isInteger(toId)) return;
    const toSocket = online.get(toId);
    if (toSocket) {
      io.to(toSocket).emit('call:ended', { from: me.id });
    }
  });

  socket.on('call:signal', (payload) => {
    const toId = Number(payload && payload.to);
    const data = payload && payload.data;
    if (!Number.isInteger(toId) || !data) return;
    const toSocket = online.get(toId);
    if (toSocket) {
      io.to(toSocket).emit('call:signal', { from: me.id, data });
    }
  });

  /* ---------- ОТКЛЮЧЕНИЕ ---------- */
  socket.on('disconnect', () => {
    // Только если это тот же сокет (защита от реконнектов)
    if (online.get(me.id) === socket.id) {
      online.delete(me.id);
      db.prepare('UPDATE users SET last_seen = ? WHERE id = ?').run(now(), me.id);
      broadcastOnline();
      socket.broadcast.emit('user:offline', { id: me.id });

      // Сообщаем всем, с кем мог быть звонок — принудительно завершить
      socket.broadcast.emit('call:ended', { from: me.id });
    }
  });
});

/* ============================================================
   ЗАПУСК
============================================================ */
server.listen(PORT, () => {
  console.log(`\n  🚀  Mini Messenger запущен:`);
  console.log(`  →  http://localhost:${PORT}\n`);
});