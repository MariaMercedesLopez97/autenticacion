function isValidEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
}

function isValidPassword(password) {
    const passwordRegex = /^(?=.*[A-Z])(?=.*\d)[A-Za-z\d]{8,}$/;
    return passwordRegex.test(password);
}

function validateRegistration(req, res, next) {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ message: 'Todos los campos deben ser completados' });
    }

    const sanitizedEmail = email.trim().toLowerCase();
    
    if (!isValidEmail(sanitizedEmail)) {
        return res.status(400).json({ message: 'Email inválido' });
    }

    if (!isValidPassword(password)) {
        return res.status(400).json({ message: 'La contraseña no cumple los requisitos de seguridad' });
    }

    req.sanitizedEmail = sanitizedEmail;
    next();
}

module.exports = {
    isValidEmail,
    isValidPassword,
    validateRegistration
};