const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const db = require('./db');
require('dotenv').config();

const app = express();
app.use(bodyParser.json());

app.post('/register', (req, res) => {
    const { email, password } = req.body;
    console.log(req.body);
    db.get('SELECT * FROM users WHERE email = ?', [email], (err, user) => {
        if (err) return res.status(500).json({ message: 'Internal server error' });
        if (user) return res.status(400).json({ message: 'Email already exists' });

        const hashedPassword = bcrypt.hashSync(password, 8);
        db.run('INSERT INTO users (email, password) VALUES (?, ?)', [email, hashedPassword], function (err) {
            if (err) return res.status(500).json({ message: 'Internal server error' });
            res.status(201).json({ message: 'User created', userId: this.lastID });
        });
    });
});

app.post('/login', (req, res) => {
    const { email, password } = req.body;
    db.get('SELECT * FROM users WHERE email = ?', [email], (err, user) => {
        if (err) return res.status(500).json({ message: 'Internal server error' });
        if (!user) return res.status(400).json({ message: 'Invalid email or password' });

        const passwordIsValid = bcrypt.compareSync(password, user.password);
        if (!passwordIsValid) return res.status(400).json({ message: 'Invalid email or password' });

        const token = jwt.sign({ id: user.id }, process.env.SECRET, { expiresIn: 86400 });
        res.status(200).json({ auth: true, token });
    });
});

module.exports = app;
