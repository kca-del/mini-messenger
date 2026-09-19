// db.js — инициализация SQLite через better-sqlite3
const Database = require('better-sqlite3');
const path = require('path');

const db = new Database(path.join(__dirname, 'messenger.db'));

db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

// Пользователи
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT NOT NULL UNIQUE COLLATE NOCASE,
    display_name  TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    color         TEXT NOT NULL DEFAULT '#7C5CFF',
    bio           TEXT DEFAULT '',
    created_at    INTEGER NOT NULL,
    last_seen     INTEGER NOT NULL
  );
`);

// Сообщения
db.exec(`
  CREATE TABLE IF NOT EXISTS messages (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    from_id     INTEGER NOT NULL,
    to_id       INTEGER NOT NULL,
    text        TEXT NOT NULL,
    created_at  INTEGER NOT NULL,
    edited_at   INTEGER,
    read_at     INTEGER,
    deleted_for_all INTEGER DEFAULT 0,
    deleted_for_sender INTEGER DEFAULT 0,
    deleted_for_receiver INTEGER DEFAULT 0,
    FOREIGN KEY (from_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (to_id)   REFERENCES users(id) ON DELETE CASCADE
  );
`);

db.exec(`
  CREATE INDEX IF NOT EXISTS idx_messages_dialog
    ON messages (from_id, to_id, created_at);
`);

// Закреплённые чаты (для каждого пользователя свой список)
db.exec(`
  CREATE TABLE IF NOT EXISTS pinned_chats (
    user_id    INTEGER NOT NULL,
    peer_id    INTEGER NOT NULL,
    pinned_at  INTEGER NOT NULL,
    PRIMARY KEY (user_id, peer_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (peer_id) REFERENCES users(id) ON DELETE CASCADE
  );
`);

// Закреплённые сообщения в чате
db.exec(`
  CREATE TABLE IF NOT EXISTS pinned_messages (
    user_id    INTEGER NOT NULL,
    peer_id    INTEGER NOT NULL,
    message_id INTEGER NOT NULL,
    pinned_at  INTEGER NOT NULL,
    PRIMARY KEY (user_id, peer_id, message_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (message_id) REFERENCES messages(id) ON DELETE CASCADE
  );
`);

// Миграции — добавляем поля, если их нет (для старых баз)
function tryAddColumn(table, column, definition) {
  try {
    db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`);
  } catch (e) {
    // Поле уже существует — ничего не делаем
  }
}

tryAddColumn('users', 'bio', "TEXT DEFAULT ''");
tryAddColumn('messages', 'edited_at', 'INTEGER');
tryAddColumn('messages', 'deleted_for_all', 'INTEGER DEFAULT 0');
tryAddColumn('messages', 'deleted_for_sender', 'INTEGER DEFAULT 0');
tryAddColumn('messages', 'deleted_for_receiver', 'INTEGER DEFAULT 0');

module.exports = db;
