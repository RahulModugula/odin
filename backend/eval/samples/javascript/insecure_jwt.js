// Intentionally vulnerable: insecure JWT handling. For eval only.
const jwt = require('jsonwebtoken');
const express = require('express');
const app = express();

// UNSAFE: jwt.decode() does not verify signature — any payload can be forged
function getUserFromToken(token) {
    const payload = jwt.decode(token);
    return payload.userId;
}

app.get('/profile', (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    const userId = getUserFromToken(token);
    res.json({ userId });
});

app.get('/admin', (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    // Trusting unverified claims for authorization — critical flaw
    const payload = jwt.decode(token);
    if (payload.role === 'admin') {
        res.send('admin panel');
    } else {
        res.status(403).send('forbidden');
    }
});
