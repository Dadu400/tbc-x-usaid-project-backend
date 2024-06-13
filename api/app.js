const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');

require('dotenv').config();

const app = express();
app.use(bodyParser.json());

const db = require('../db/db');
db.connect();

app.post('/register', (req, res) => {
    const { email, password } = req.body;
    console.log(req.body);
    db.query('SELECT * FROM credentials WHERE email = $1', [email], (err, result) => {
        if (err) {
            return res.status(500).json({ message: 'Internal server error' });
        }
        if (result.rows.length > 0) {
            return res.status(400).json({ message: 'Email already exists' });
        }

        const hashedPassword = bcrypt.hashSync(password, 8);
        db.query('INSERT INTO credentials (email, password) VALUES ($1, $2) RETURNING id', [email, hashedPassword], (err, result) => {
            if (err) {
                return res.status(500).json({ message: 'Internal server error' })
            };
            res.status(201).json({ message: 'User created', userId: result.rows[0].id });
        });
    });
});

app.post('/login', (req, res) => {
    const { email, password } = req.body;
    db.query('SELECT * FROM credentials WHERE email = $1', [email], (err, result) => {
        if (err) {
            return res.status(500).json({ message: 'Internal server error' })
        };
        if (result.rows.length === 0) {
            return res.status(400).json({ message: 'Invalid email or password' })
        };

        const user = result.rows[0];
        const passwordIsValid = bcrypt.compareSync(password, user.password);
        if (!passwordIsValid) {
            return res.status(400).json({ message: 'Invalid email or password' })
        };

        const token = jwt.sign({ id: user.id }, process.env.SECRET, { expiresIn: 86400 });
        res.status(200).json({ auth: true, token });
    });
});

app.post('/change-password', (req, res) => {
    const { email, oldPassword, newPassword } = req.body;
    db.query('SELECT * FROM credentials WHERE email = $1', [email], (err, result) => {
        if (err) {
            return res.status(500).json({ message: 'Internal server error' });
        }
        if (result.rows.length === 0) {
            return res.status(400).json({ message: 'Invalid email' });
        }

        const user = result.rows[0];
        const passwordIsValid = bcrypt.compareSync(oldPassword, user.password);
        if (!passwordIsValid) {
            return res.status(400).json({ message: 'Invalid password' });
        }

        const hashedPassword = bcrypt.hashSync(newPassword, 8);
        db.query('UPDATE credentials SET password = $1 WHERE email = $2', [hashedPassword, email], (err, result) => {
            if (err) {
                return res.status(500).json({ message: 'Internal server error' });
            }
            res.status(200).json({ message: 'Password changed successfully' });
        });
    });
});

module.exports = app;
