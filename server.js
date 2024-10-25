// server.js
const express = require('express');
const mysql = require('mysql2');
const bodyParser = require('body-parser');
const cors = require('cors');
require('dotenv').config();

// Ініціалізація сервера
const app = express();
const port = 3000;

// Middleware
app.use(cors());
app.use(bodyParser.json());

// Налаштування з'єднання з базою даних
const db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    port: process.env.DB_PORT,
});

// Підключення до бази даних
db.connect((err) => {
    if (err) {
        console.error('Помилка підключення до бази даних:', err);
        return;
    }
    console.log('Підключено до бази даних.');
});

// Роут для запису на пірсинг
app.post('/api/appointments', (req, res) => {
    const { clientName, service, date } = req.body;

    const query = 'INSERT INTO appointments (client_name, service, date) VALUES (?, ?, ?)';
    db.query(query, [clientName, service, date], (err, results) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.status(201).json({ id: results.insertId });
    });
});

// Запуск сервера
app.listen(port, () => {
    console.log(`Сервер запущено на http://localhost:${port}`);
});
