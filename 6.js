const jwt = require('jsonwebtoken');

const JWT_SECRET = process.env.JWT_SECRET; // must be strong & kept secret
const EXPECTED_ISSUER = 'your-app';
const EXPECTED_AUDIENCE = 'your-app-users';

function authMiddleware(req, res, next) {
    try {
        const authHeader = req.headers['authorization'];

        // Require Authorization header
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({ success: false, message: 'Missing or invalid Authorization header' });
        }

        const token = authHeader.split(' ')[1];

        // Verify token with strict options
        const decoded = jwt.verify(token, JWT_SECRET, {
            algorithms: ['HS256'],          // explicitly allow only expected algorithm
            issuer: EXPECTED_ISSUER,        // validate issuer
            audience: EXPECTED_AUDIENCE,    // validate audience
            clockTolerance: 5               // small leeway for clock skew (seconds)
        });

        // Ensure required claims exist
        if (!decoded || !decoded.sub) {
            return res.status(401).json({ success: false, message: 'Invalid token payload' });
        }

        // Attach user identity to request (do NOT trust arbitrary fields)
        req.user = {
            id: decoded.sub,
            role: decoded.role || 'user'
        };

        return next();

    } catch (err) {
        // Avoid leaking details
        return res.status(401).json({ success: false, message: 'Unauthorized' });
    }
}

module.exports = authMiddleware;