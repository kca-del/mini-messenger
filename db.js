// db.js — инициализация SQLite через better-sqlite3
const Database = require('better-sqlite3');
const path = require('path');

// Файл базы данных рядом с проектом
const db = new Database(path.join(__dirname, 'messenger.db'));

// Включаем WAL и внешние ключи для производительности и целостности
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

// Таблица пользователей
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT NOT NULL UNIQUE COLLATE NOCASE,
    display_name  TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    color         TEXT NOT NULL DEFAULT '#7C5CFF',
    created_at    INTEGER NOT NULL,
    last_seen     INTEGER NOT NULL
  );
`);

// Таблица сообщений
db.exec(`
  CREATE TABLE IF NOT EXISTS messages (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    from_id     INTEGER NOT NULL,
    to_id       INTEGER NOT NULL,
    text        TEXT NOT NULL,
    created_at  INTEGER NOT NULL,
    read_at     INTEGER,
    FOREIGN KEY (from_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (to_id)   REFERENCES users(id) ON DELETE CASCADE
  );
`);

db.exec(`
  CREATE INDEX IF NOT EXISTS idx_messages_dialog
    ON messages (from_id, to_id, created_at);
`);

module.exports = db;