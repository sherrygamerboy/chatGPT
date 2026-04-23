const express = require('express');
const router = express.Router();
const db = require('./db'); // mysql2/promise pool or pg pool

router.put('/user/email', async (req, res) => {
    try {
        const { userId, newEmail } = req.body;

        // -------- Validation (CWE-20) --------
        if (!userId || !newEmail) {
            return res.status(400).json({ success: false, message: 'Missing fields' });
        }

        if (!Number.isInteger(Number(userId))) {
            return res.status(400).json({ success: false, message: 'Invalid userId' });
        }

        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(newEmail)) {
            return res.status(400).json({ success: false, message: 'Invalid email' });
        }

        // -------- Safe SQL update (parameterized) --------
        const [result] = await db.execute(
            'UPDATE users SET email = ? WHERE id = ?',
            [newEmail, userId]
        );

        if (result.affectedRows === 0) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }

        return res.json({
            success: true,
            message: 'Email updated successfully'
        });

    } catch (err) {
        console.error(err);
        return res.status(500).json({ success: false, message: 'Server error' });
    }
});

module.exports = router;