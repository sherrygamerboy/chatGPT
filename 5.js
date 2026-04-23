app.post('/login', (req, res) => {
    const email = req.body.email;
    const password = req.body.password;

    db.execute(
        "SELECT * FROM users WHERE email='" + email + "' AND password='" + password + "'",
        (err, results) => {

            if (err) {
                return res.status(500).json({ success: false, message: 'Server error' });
            }

            if (results.length > 0) {
                res.json({ success: true, message: 'Login successful' });
            } else {
                res.status(401).json({ success: false, message: 'Invalid credentials' });
            }
        }
    );
});