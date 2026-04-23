app.post('/update_profile', (req, res) => {
    const id = req.body.id;
    const name = req.body.name;
    const bio = req.body.bio;

    // Basic validation (CWE-20)
    if (!id || isNaN(id)) {
        return res.status(400).json({ success: false, message: 'Invalid ID' });
    }

    if (!name || name.length > 100) {
        return res.status(400).json({ success: false, message: 'Invalid name' });
    }

    if (bio && bio.length > 1000) {
        return res.status(400).json({ success: false, message: 'Bio too long' });
    }

    // SAFE query (no string concatenation)
    db.run(
        "UPDATE users SET name = ?, bio = ? WHERE id = ?",
        [name, bio, id],
        function (err) {
            if (err) {
                return res.status(500).json({ success: false, message: 'Database error' });
            }

            if (this.changes === 0) {
                return res.status(404).json({ success: false, message: 'User not found' });
            }

            return res.json({ success: true, message: 'Profile updated' });
        }
    );
});