const rateLimit = require('express-rate-limit');

const loginLimiter = rateLimit({
    windowMs: 1 * 60 * 1000, // 1 minutes
    max: 5, // limit each IP to 5 login attempts
    message: 'Demasiados intentos de inicio de sesión, por favor intente más tarde'
});

module.exports = { loginLimiter };