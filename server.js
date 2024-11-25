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

// реєстрація нового користувача\адміністратора
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

// логін користувача\адміністратора
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

// логаут користувача\адміністратора
app.post('/logout', (req, res) => {
    const token = req.headers['authorization'] && req.headers['authorization'].split(' ')[1];
    if (token) {
        blacklistedTokens.add(token); // додаємо токен до чорного списку
    }
    res.status(200).json({ message: 'Успішний вихід із системи' });
});

// можливість додававання доступних днів для запису 
// виключно для адміністраторів
app.post('/admin/free_days', authenticateToken(['admin']), async (req, res) => {
    const { date, is_available } = req.body;

    if (!date || is_available === undefined) {
        return res.status(400).json({ message: 'Дата та доступність повинні бути заповнені.' });
    }

    const query = 'INSERT INTO free_days (date, is_available) VALUES (?, ?)';

    try {
        const [result] = await getConnection().then((connection) =>
            connection.execute(query, [date, is_available])
        );
        res.send('День додано');
    } catch (error) {
        handleError(res, error);
    }
});


// можливість додававання доступних годин в дні для запису 
// виключно для адміністраторів.
app.post('/admin/free_hours', authenticateToken(['admin']), async (req, res) => {
    const { date, time, is_available } = req.body;

    if (!date || !time || is_available === undefined) {
        return res.status(400).json({ message: 'Дата, час та доступність повинні бути заповнені.' });
    }

    // перевірка на доступний день у таблиці бази даних.
    const queryDay = 'SELECT id FROM free_days WHERE date = ?';
    const [dayResult] = await getConnection().then((connection) =>
        connection.execute(queryDay, [date])
    );

    if (dayResult.length === 0) {
        return res.status(404).json({ message: 'Цей день не знайдений у таблиці free_days.' });
    }

    const freeDayId = dayResult[0].id;

    const queryHour = 'INSERT INTO free_hours (free_day_id, time, is_available) VALUES (?, ?, ?)';
    try {
        await getConnection().then((connection) =>
            connection.execute(queryHour, [freeDayId, time, is_available])
        );
        res.send('Година додана для цього дня');
    } catch (error) {
        handleError(res, error);
    }
});

// можливість перегляду доступних днів для запису.
app.get('/free_days', authenticateToken(['user', 'admin']), async (req, res) => {
    const query = 'SELECT * FROM free_days;';
    try {
        const [results] = await getConnection().then((connection) =>
            connection.execute(query)
        );

        console.log('Free days results:', results);  // Логування результатів запиту

        if (results.length === 0) {
            return res.status(404).json({ message: 'Немає доступних днів.' });
        }

        res.json(results);  // Повернення доступних днів
    } catch (error) {
        handleError(res, error);
    }
});

// можливість перегляду доступних годин для запису.
app.get('/free_hours', async (req, res) => {
    const query = 'SELECT * FROM free_hours';

    try {
        const [rows] = await getConnection().then((connection) => connection.execute(query));
        res.json(rows);
    } catch (error) {
        handleError(res, error);
    }
});

// можливість додавання нової послуги виключно для адміністраторів.

app.post('/admin/services', authenticateToken(['admin']), [
    body('name').isLength({ min: 3 }).withMessage('Назва послуги повинна бути не менше 3 символів'),
    body('description').isLength({ min: 5 }).withMessage('Опис послуги повинний бути не менше 5 символів'),
    body('price').isFloat({ min: 0 }).withMessage('Ціна повинна бути числом більшим за 0'),
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { name, description, price } = req.body;

    const query = 'INSERT INTO services (name, description, price) VALUES (?, ?, ?)';

    try {
        await getConnection().then((connection) =>
            connection.execute(query, [name, description, price])
        );
        res.send('Нова послуга додана');
    } catch (error) {
        handleError(res, error);
    }
});

// можливість оновлення вже існуючої послуги виключно для адміністраторів.

app.put('/admin/services/:id', authenticateToken(['admin']), [
    body('name').optional().isLength({ min: 3 }).withMessage('Назва послуги повинна бути не менше 3 символів'),
    body('description').optional().isLength({ min: 5 }).withMessage('Опис послуги повинний бути не менше 5 символів'),
    body('price').optional().isFloat({ min: 0 }).withMessage('Ціна повинна бути числом більшим за 0'),
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { name, description, price } = req.body;
    const { id } = req.params; // id послуги, яку потрібно оновити.

    const queryCheckService = 'SELECT * FROM services WHERE id = ?';
    const [serviceResult] = await getConnection().then((connection) =>
        connection.execute(queryCheckService, [id])
    );

    if (serviceResult.length === 0) {
        return res.status(404).json({ message: 'Послугу не знайдено' });
    }

    const queryUpdateService = `
        UPDATE services
        SET name = COALESCE(?, name), description = COALESCE(?, description), price = COALESCE(?, price)
        WHERE id = ?
    `;

    try {
        await getConnection().then((connection) =>
            connection.execute(queryUpdateService, [name, description, price, id])
        );
        res.send('Послугу оновлено');
    } catch (error) {
        handleError(res, error);
    }
});

// отримання послуг (доступно для всіх авторизованих користувачів).
app.get('/services', authenticateToken(), async (req, res) => {
    const query = 'SELECT * FROM services';

    try {
        const [rows] = await getConnection().then((connection) => connection.execute(query));
        res.json(rows);
    } catch (error) {
        handleError(res, error);
    }
});


// запускаємо сервер.
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Сервер запущено на порту ${PORT}`);
});