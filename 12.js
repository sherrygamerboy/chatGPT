const db = require('../db'); // mysql2/promise pool

/**
 * Search users safely
 * GET /search?query=...
 */
async function searchUsers(req, res) {
    try {
        const query = req.query.query;

        // -------------------------
        // Input validation (CWE-20)
        // -------------------------
        if (!query || typeof query !== 'string') {
            return res.status(400).json({
                success: false,
                message: 'Invalid search query'
            });
        }

        const trimmedQuery = query.trim();

        if (trimmedQuery.length < 2 || trimmedQuery.length > 50) {
            return res.status(400).json({
                success: false,
                message: 'Query length out of range'
            });
        }

        // -------------------------
        // Safe parameterized query (CWE-89 prevention)
        // -------------------------
        const [rows] = await db.execute(
            "SELECT id, name, email FROM users WHERE name LIKE ? LIMIT 20",
            [`%${trimmedQuery}%`]
        );

        return res.json({
            success: true,
            data: rows
        });

    } catch (err) {
        // -------------------------
        // OWASP A10-style safe error handling
        // -------------------------
        console.error('Search error:', err);

        return res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
}

module.exports = { searchUsers };