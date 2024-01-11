const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const json2csv = require('json2csv');
const bcrypt = require('bcrypt');
const saltRounds = 10;
const jwt = require('jsonwebtoken');
const fs = require('fs');

const app = express();
const port = 3000;

app.use(bodyParser.json());

const db = new sqlite3.Database('warehouse.db');

// Создаем таблицу для хранения пользователей
db.run(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT
  )
`);

// Создаем таблицу для хранения товаров
db.run(`
  CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    name TEXT,
    quantity INTEGER
  )
`);

// Эндпоинт для регистрации нового пользователя
app.post('/register', (req, res) => {
  const { username, password } = req.body;

  // Хэширование пароля перед сохранением в базе данных
  bcrypt.hash(password, saltRounds, (err, hash) => {
    if (err) {
      console.error(err);
      res.status(500).json({ error: 'Internal Server Error' });
    } else {
      // Вставка пользователя в базу данных
      const stmt = db.prepare('INSERT INTO users (username, password) VALUES (?, ?)');
      stmt.run(username, hash);
      stmt.finalize();
      res.json({ message: 'User registered successfully' });
    }
  });
});

// Эндпоинт для аутентификации и получения токена
app.post('/login', (req, res) => {
  const { username, password } = req.body;

  // Поиск пользователя в базе данных
  db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
    if (err) {
      console.error(err);
      res.status(500).json({ error: 'Internal Server Error' });
    } else if (!user) {
      res.status(401).json({ error: 'Invalid username or password' });
    } else {
      // Сравнение хэша пароля
      bcrypt.compare(password, user.password, (err, result) => {
        if (result) {
          // Создание JWT токена
          const token = jwt.sign({ id: user.id, username: user.username }, 'secret_key');
          res.json({ token });
        } else {
          res.status(401).json({ error: 'Invalid username or password' });
        }
      });
    }
  });
});

// Прочие эндпоинты остаются без изменений

// Эндпоинт для получения информации о товарах пользователя
app.get('/products', authenticateToken, (req, res) => {
  const userId = req.user.id;

  db.all('SELECT * FROM products WHERE user_id = ?', [userId], (err, rows) => {
    if (err) {
      console.error(err);
      res.status(500).json({ error: 'Internal Server Error' });
    } else {
      res.json(rows);
    }
  });
});

app.post('/products', authenticateToken, (req, res) => {
  const userId = req.user.id;
  const products = req.body.products;

  // Предполагаем, что products - это массив объектов { name, quantity }

  // Удаление существующих записей для пользователя
  db.run('DELETE FROM products WHERE user_id = ?', [userId], (err) => {
    if (err) {
      console.error(err);
      res.status(500).json({ error: 'Internal Server Error' });
    } else {
      // Вставка новых данных
      const stmt = db.prepare('INSERT INTO products (user_id, name, quantity) VALUES (?, ?, ?)');
      products.forEach((product) => {
        stmt.run(userId, product.name, product.quantity);
      });
      stmt.finalize();
      res.json({ message: 'Products updated successfully' });
    }
  });
});


// Создание тестовых данных
app.get('/createTestData', (req, res) => {
  // Предполагаем, что createTestData - это массив объектов { user_id, name, quantity }

  const stmt = db.prepare('INSERT INTO products (user_id, name, quantity) VALUES (?, ?, ?)');
  req.query.createTestData.forEach((product) => {
    stmt.run(product.user_id, product.name, product.quantity);
  });
  stmt.finalize();
  res.json({ message: 'Test data created successfully' });
});

// Middleware для аутентификации токена
function authenticateToken(req, res, next) {
  const token = req.headers['authorization'];

  if (!token) return res.status(401).json({ error: 'Unauthorized' });

  // Ваш механизм проверки токена

  // Пример: предполагаем, что токен в формате "Bearer <токен>"
  jwt.verify(token.split(' ')[1], 'secret_key', (err, user) => {
    if (err) {
      console.error(err);
      res.status(403).json({ error: 'Forbidden' });
    } else {
      req.user = user;
      next();
    }
  });
}

// Запуск сервера
app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
