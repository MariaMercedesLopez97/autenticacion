const express = require('express');
const AuthController = require('../controllers/auth.controller');
const { validateRegistration } = require('../middleware/validation.middleware');
const { loginLimiter } = require('../middleware/rate-limit.middleware');

const router = express.Router();

router.get('/csrf-token', (req, res) => {
    res.json({ csrfToken: req.csrfToken() });
});
router.post('/register', validateRegistration, AuthController.register);
router.post('/login', loginLimiter, AuthController.login);

module.exports = router;