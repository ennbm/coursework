require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');
const cors = require('cors');
const path = require('path');
const swaggerUi = require('swagger-ui-express');
const swaggerDocument = require('./swagger.json');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));


// Swagger setup
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocument));

const dbConfig = {
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
};

const pool = mysql.createPool(dbConfig);

const getConnection = async () => {
    return await pool.getConnection();
};

const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';
const JWT_EXPIRATION = '1h';
const BCRYPT_SALT_ROUNDS = 12;
const blacklistedTokens = new Set();

const handleError = (res, error) => {
    console.error(error);
    res.status(500).json({ message: 'Сталася помилка, спробуйте пізніше.', error: error.message });
};

// середовище для аутентифікації.
const authenticateToken = (requiredRoles = []) => async (req, res, next) => {
    const token = req.headers['authorization'] && req.headers['authorization'].split(' ')[1]; // отримуємо токен.

    if (!token) return res.status(401).json({ message: 'Токен не надано' });

    if (blacklistedTokens.has(token)) {
        return res.status(403).json({ message: 'Токен більше недійсний' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ message: 'Недійсний токен' });
        req.user = user;

        if (requiredRoles.length && !requiredRoles.includes(user.role)) {
            return res.status(403).json({ message: `Доступ заборонено для ролі: ${user.role}` });
        }

        next();
    });
};

// Реєстрація нового користувача
app.post('/register', [
    body('username').isLength({ min: 5 }).withMessage('Ім\'я повинно бути не менше 5 символів'),
    body('password').isLength({ min: 8 }).withMessage('Пароль повинен бути не менше 8 символів'),
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { username, password, role = 'user' } = req.body;

    try {
        const hashedPassword = await bcrypt.hash(password, BCRYPT_SALT_ROUNDS);
        const query = 'INSERT INTO users (username, password, role) VALUES (?, ?, ?)';
        const connection = await getConnection();
        await connection.execute(query, [username, hashedPassword, role]);
        res.send('Користувача зареєстровано');
    } catch (error) {
        handleError(res, error);
    }
});

// Логін користувача
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const query = 'SELECT * FROM users WHERE username = ?';

    try {
        const [rows] = await getConnection().then((connection) => {
            return connection.execute(query, [username]);
        });

        if (rows.length > 0 && await bcrypt.compare(password, rows[0].password)) {
            const token = jwt.sign(
                { id: rows[0].id, role: rows[0].role },
                JWT_SECRET,
                { expiresIn: JWT_EXPIRATION }
            );
            res.json({ token });
        } else {
            res.status(401).send('Неправильне ім\'я користувача або пароль');
        }
    } catch (error) {
        handleError(res, error);
    }
});

// Логаут користувача
app.post('/logout', (req, res) => {
    const token = req.headers['authorization'] && req.headers['authorization'].split(' ')[1];
    if (token) {
        blacklistedTokens.add(token); // Додаємо токен до чорного списку
    }
    res.status(200).json({ message: 'Успішний вихід із системи' });
});

// Запускаємо сервер.
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Сервер запущено на порту ${PORT}`);
});