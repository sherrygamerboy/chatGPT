const express = require('express');
const bcrypt = require('bcrypt');
const router = express.Router();

// Example: using mysql2/promise pool
const db = require('./db'); // your DB connection (pool)

// POST /login
router.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        // Basic validation
        if (!email || !password) {
            return res.status(400).json({ success: false, message: 'Invalid request' });
        }

        // Query user (parameterized → prevents SQL injection)
        const [rows] = await db.execute(
            'SELECT id, email, password_hash FROM users WHERE email = ? LIMIT 1',
            [email]
        );

        if (rows.length === 0) {
            return res.status(401).json({ success: false, message: 'Invalid credentials' });
        }

        const user = rows[0];

        // Compare password with bcrypt hash
        const match = await bcrypt.compare(password, user.password_hash);

        if (!match) {
            return res.status(401).json({ success: false, message: 'Invalid credentials' });
        }

        // Success response
        return res.json({
            success: true,
            message: 'Login successful',
            user: {
                id: user.id,
                email: user.email
            }
        });

    } catch (err) {
        console.error(err);
        return res.status(500).json({ success: false, message: 'Server error' });
    }
});

module.exports = router;