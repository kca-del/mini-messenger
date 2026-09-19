// server.js — Express + Socket.IO + JWT + SQLite + WebRTC
const path = require('path');
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const db = require('./db');

const JWT_SECRET = process.env.JWT_SECRET || 'change-me-in-production-please-32-chars-min';

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' } });

app.use(express.json({ limit: '1mb' }));
app.use(express.static(path.join(__dirname, 'public')));

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
  return jwt.sign({ uid: user.id, username: user.username }, JWT_SECRET, { expiresIn: '30d' });
}
function verifyToken(token) {
  try { return jwt.verify(token, JWT_SECRET); } catch { return null; }
}
function publicUser(u) {
  return {
    id: u.id,
    username: u.username,
    displayName: u.display_name,
    color: u.color,
    bio: u.bio || '',
    lastSeen: u.last_seen
  };
}

/* ============ HTTP API ============ */

// Регистрация
app.post('/api/register', async (req, res) => {
  try {
    const username = String(req.body.username || '').trim().toLowerCase();
    const displayName = sanitize(req.body.displayName || username, 40);
    const password = String(req.body.password || '');

    if (!/^[a-z0-9_]{3,20}$/.test(username)) {
      return res.status(400).json({ error: 'Логин: 3–20 символов, латиница, цифры, _' });
    }
    if (password.length < 4) return res.status(400).json({ error: 'Пароль минимум 4 символа' });
    if (!displayName) return res.status(400).json({ error: 'Введите отображаемое имя' });

    const existing = db.prepare('SELECT id FROM users WHERE username = ?').get(username);
    if (existing) return res.status(409).json({ error: 'Этот юзернейм занят' });

    const hash = await bcrypt.hash(password, 10);
    const ts = now();

    const info = db.prepare(`
      INSERT INTO users (username, display_name, password_hash, color, created_at, last_seen)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(username, displayName, hash, pickColor(), ts, ts);

    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(info.lastInsertRowid);
    res.json({ token: issueToken(user), user: publicUser(user) });
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
    res.json({ token: issueToken(user), user: publicUser(user) });
  } catch (e) {
    console.error('login error', e);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// Авторизация
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

// Обновить профиль
app.patch('/api/me', auth, (req, res) => {
  const displayName = sanitize(req.body.displayName || req.user.display_name, 40);
  const bio = sanitize(req.body.bio || '', 200);

  db.prepare('UPDATE users SET display_name = ?, bio = ? WHERE id = ?')
    .run(displayName, bio, req.user.id);

  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
  res.json({ user: publicUser(user) });
});

// Поиск пользователей по @username (без полного списка)
app.get('/api/search', auth, (req, res) => {
  const q = String(req.query.q || '').trim().toLowerCase().replace(/^@/, '');

  if (q.length < 2) return res.json({ users: [] });

  const users = db.prepare(`
    SELECT id, username, display_name, color, bio, last_seen
    FROM users
    WHERE id != ? AND (
      username LIKE ? OR
      display_name LIKE ?
    )
    ORDER BY username COLLATE NOCASE
    LIMIT 20
  `).all(req.user.id, `${q}%`, `%${q}%`);

  res.json({ users: users.map(publicUser) });
});

// Найти конкретного по username
app.get('/api/user/:username', auth, (req, res) => {
  const username = String(req.params.username || '').trim().toLowerCase().replace(/^@/, '');
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  if (!user) return res.status(404).json({ error: 'Пользователь не найден' });
  if (user.id === req.user.id) return res.status(400).json({ error: 'Это вы' });
  res.json({ user: publicUser(user) });
});

// Мои чаты (кто-то, с кем была переписка)
app.get('/api/chats', auth, (req, res) => {
  const me = req.user.id;

  const rows = db.prepare(`
    SELECT
      CASE WHEN m.from_id = ? THEN m.to_id ELSE m.from_id END AS peer_id,
      MAX(m.created_at) AS last_at
    FROM messages m
    WHERE (m.from_id = ? OR m.to_id = ?)
      AND NOT (m.deleted_for_all = 1)
      AND NOT (m.from_id = ? AND m.deleted_for_sender = 1)
      AND NOT (m.to_id = ? AND m.deleted_for_receiver = 1)
    GROUP BY peer_id
    ORDER BY last_at DESC
  `).all(me, me, me, me, me);

  const out = [];
  for (const row of rows) {
    const peer = db.prepare('SELECT * FROM users WHERE id = ?').get(row.peer_id);
    if (!peer) continue;

    const last = db.prepare(`
      SELECT id, from_id AS fromId, to_id AS toId, text, created_at AS createdAt, read_at AS readAt, edited_at AS editedAt
      FROM messages
      WHERE ((from_id = ? AND to_id = ?) OR (from_id = ? AND to_id = ?))
        AND deleted_for_all = 0
        AND NOT (from_id = ? AND deleted_for_sender = 1)
        AND NOT (to_id = ? AND deleted_for_receiver = 1)
      ORDER BY created_at DESC
      LIMIT 1
    `).get(me, peer.id, peer.id, me, me, me);

    const unread = db.prepare(`
      SELECT COUNT(*) AS c FROM messages
      WHERE from_id = ? AND to_id = ? AND read_at IS NULL
        AND deleted_for_all = 0
        AND NOT (to_id = ? AND deleted_for_receiver = 1)
    `).get(peer.id, me, me).c;

    const pinned = db.prepare('SELECT 1 FROM pinned_chats WHERE user_id = ? AND peer_id = ?')
      .get(me, peer.id);

    out.push({
      peer: publicUser(peer),
      last: last || null,
      unread,
      pinned: !!pinned,
      lastAt: row.last_at
    });
  }

  // Сортируем: сначала закреплённые, потом по дате
  out.sort((a, b) => {
    if (a.pinned !== b.pinned) return a.pinned ? -1 : 1;
    return (b.lastAt || 0) - (a.lastAt || 0);
  });

  res.json({ chats: out });
});

// Закрепить / открепить чат
app.post('/api/chats/:peerId/pin', auth, (req, res) => {
  const peerId = Number(req.params.peerId);
  if (!Number.isInteger(peerId)) return res.status(400).json({ error: 'Некорректный id' });

  const existing = db.prepare('SELECT 1 FROM pinned_chats WHERE user_id = ? AND peer_id = ?')
    .get(req.user.id, peerId);

  if (existing) {
    db.prepare('DELETE FROM pinned_chats WHERE user_id = ? AND peer_id = ?').run(req.user.id, peerId);
    res.json({ pinned: false });
  } else {
    db.prepare('INSERT INTO pinned_chats (user_id, peer_id, pinned_at) VALUES (?, ?, ?)')
      .run(req.user.id, peerId, now());
    res.json({ pinned: true });
  }
});

// История сообщений
app.get('/api/messages/:userId', auth, (req, res) => {
  const otherId = Number(req.params.userId);
  if (!Number.isInteger(otherId)) return res.status(400).json({ error: 'Некорректный id' });

  const me = req.user.id;

  const rows = db.prepare(`
    SELECT id, from_id AS fromId, to_id AS toId, text,
           created_at AS createdAt, edited_at AS editedAt, read_at AS readAt
    FROM messages
    WHERE ((from_id = ? AND to_id = ?) OR (from_id = ? AND to_id = ?))
      AND deleted_for_all = 0
      AND NOT (from_id = ? AND deleted_for_sender = 1)
      AND NOT (to_id = ? AND deleted_for_receiver = 1)
    ORDER BY created_at ASC
    LIMIT 500
  `).all(me, otherId, otherId, me, me, me);

  // Помечаем прочитанными
  db.prepare(`
    UPDATE messages SET read_at = ?
    WHERE from_id = ? AND to_id = ? AND read_at IS NULL
  `).run(now(), otherId, me);

  res.json({ messages: rows });
});

// Закреплённые сообщения в чате
app.get('/api/messages/:userId/pinned', auth, (req, res) => {
  const otherId = Number(req.params.userId);
  if (!Number.isInteger(otherId)) return res.status(400).json({ error: 'Некорректный id' });

  const rows = db.prepare(`
    SELECT m.id, m.from_id AS fromId, m.to_id AS toId, m.text,
           m.created_at AS createdAt, m.edited_at AS editedAt
    FROM pinned_messages pm
    JOIN messages m ON m.id = pm.message_id
    WHERE pm.user_id = ? AND pm.peer_id = ?
    ORDER BY pm.pinned_at DESC
  `).all(req.user.id, otherId);

  res.json({ messages: rows });
});

// Закрепить / открепить сообщение
app.post('/api/messages/:id/pin', auth, (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id)) return res.status(400).json({ error: 'Некорректный id' });

  const msg = db.prepare('SELECT * FROM messages WHERE id = ?').get(id);
  if (!msg) return res.status(404).json({ error: 'Сообщение не найдено' });

  const me = req.user.id;
  const peer = msg.from_id === me ? msg.to_id : msg.from_id;

  const existing = db.prepare('SELECT 1 FROM pinned_messages WHERE user_id = ? AND peer_id = ? AND message_id = ?')
    .get(me, peer, id);

  if (existing) {
    db.prepare('DELETE FROM pinned_messages WHERE user_id = ? AND peer_id = ? AND message_id = ?')
      .run(me, peer, id);
    res.json({ pinned: false });
  } else {
    db.prepare('INSERT INTO pinned_messages (user_id, peer_id, message_id, pinned_at) VALUES (?, ?, ?, ?)')
      .run(me, peer, id, now());
    res.json({ pinned: true });
  }
});

/* ============ SOCKET.IO ============ */
const online = new Map();

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
  io.emit('online:list', [...online.keys()]);
}

io.on('connection', (socket) => {
  const me = socket.data.user;
  online.set(me.id, socket.id);
  db.prepare('UPDATE users SET last_seen = ? WHERE id = ?').run(now(), me.id);
  broadcastOnline();
  socket.broadcast.emit('user:online', { id: me.id });

  // Новое сообщение
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
        fromId: me.id, toId, text,
        createdAt: ts, editedAt: null, readAt: null
      };

      const toSocket = online.get(toId);
      if (toSocket) io.to(toSocket).emit('message:new', msg);
      socket.emit('message:new', msg);
      ack && ack({ ok: true, message: msg });
    } catch (e) {
      console.error('message:send', e);
      ack && ack({ error: 'Ошибка сервера' });
    }
  });

  // Редактировать сообщение
  socket.on('message:edit', (payload, ack) => {
    const id = Number(payload && payload.id);
    const text = sanitize(payload && payload.text, 4000);
    if (!Number.isInteger(id) || !text) return ack && ack({ error: 'Некорректные данные' });

    const msg = db.prepare('SELECT * FROM messages WHERE id = ?').get(id);
    if (!msg) return ack && ack({ error: 'Сообщение не найдено' });
    if (msg.from_id !== me.id) return ack && ack({ error: 'Можно редактировать только свои' });

    const ts = now();
    db.prepare('UPDATE messages SET text = ?, edited_at = ? WHERE id = ?').run(text, ts, id);

    const updated = {
      id, fromId: msg.from_id, toId: msg.to_id, text,
      createdAt: msg.created_at, editedAt: ts, readAt: msg.read_at
    };

    const toSocket = online.get(msg.to_id);
    if (toSocket) io.to(toSocket).emit('message:updated', updated);
    socket.emit('message:updated', updated);
    ack && ack({ ok: true, message: updated });
  });

  // Удалить сообщение (для себя / для всех)
  socket.on('message:delete', (payload, ack) => {
    const id = Number(payload && payload.id);
    const forAll = !!(payload && payload.forAll);
    if (!Number.isInteger(id)) return ack && ack({ error: 'Некорректный id' });

    const msg = db.prepare('SELECT * FROM messages WHERE id = ?').get(id);
    if (!msg) return ack && ack({ error: 'Не найдено' });

    const isMine = msg.from_id === me.id;

    if (forAll && isMine) {
      db.prepare('UPDATE messages SET deleted_for_all = 1 WHERE id = ?').run(id);
      const toSocket = online.get(msg.to_id);
      if (toSocket) io.to(toSocket).emit('message:deleted', { id, forAll: true });
      socket.emit('message:deleted', { id, forAll: true });
      ack && ack({ ok: true, forAll: true });
    } else {
      if (isMine) {
        db.prepare('UPDATE messages SET deleted_for_sender = 1 WHERE id = ?').run(id);
      } else {
        db.prepare('UPDATE messages SET deleted_for_receiver = 1 WHERE id = ?').run(id);
      }
      socket.emit('message:deleted', { id, forAll: false });
      ack && ack({ ok: true, forAll: false });
    }
  });

  socket.on('message:read', (payload) => {
    const fromId = Number(payload && payload.from);
    if (!Number.isInteger(fromId)) return;
    db.prepare(`UPDATE messages SET read_at = ? WHERE from_id = ? AND to_id = ? AND read_at IS NULL`)
      .run(now(), fromId, me.id);
    const fromSocket = online.get(fromId);
    if (fromSocket) io.to(fromSocket).emit('message:read', { by: me.id });
  });

  socket.on('typing', (payload) => {
    const toId = Number(payload && payload.to);
    const isTyping = !!(payload && payload.isTyping);
    if (!Number.isInteger(toId)) return;
    const toSocket = online.get(toId);
    if (toSocket) io.to(toSocket).emit('typing', { from: me.id, isTyping });
  });

  /* WebRTC */
  socket.on('call:invite', (payload) => {
    const toId = Number(payload && payload.to);
    const video = !!(payload && payload.video);
    if (!Number.isInteger(toId)) return;
    const toSocket = online.get(toId);
    if (!toSocket) return socket.emit('call:unavailable', { to: toId });
    io.to(toSocket).emit('call:incoming', { from: me.id, fromUser: me, video });
  });
  socket.on('call:accept', (payload) => {
    const toId = Number(payload && payload.to);
    const s = online.get(toId);
    if (s) io.to(s).emit('call:accepted', { from: me.id });
  });
  socket.on('call:reject', (payload) => {
    const toId = Number(payload && payload.to);
    const s = online.get(toId);
    if (s) io.to(s).emit('call:rejected', { from: me.id });
  });
  socket.on('call:end', (payload) => {
    const toId = Number(payload && payload.to);
    const s = online.get(toId);
    if (s) io.to(s).emit('call:ended', { from: me.id });
  });
  socket.on('call:signal', (payload) => {
    const toId = Number(payload && payload.to);
    const data = payload && payload.data;
    if (!Number.isInteger(toId) || !data) return;
    const s = online.get(toId);
    if (s) io.to(s).emit('call:signal', { from: me.id, data });
  });

  socket.on('disconnect', () => {
    if (online.get(me.id) === socket.id) {
      online.delete(me.id);
      db.prepare('UPDATE users SET last_seen = ? WHERE id = ?').run(now(), me.id);
      broadcastOnline();
      socket.broadcast.emit('user:offline', { id: me.id });
      socket.broadcast.emit('call:ended', { from: me.id });
    }
  });
});

const PORT = process.env.PORT || 8080;
server.listen(PORT, '0.0.0.0', () => {
  console.log(`Mini Messenger запущен на порту ${PORT}`);
});
