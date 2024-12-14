const jwt = require('jsonwebtoken');
const { ROLES } = require('../utils/constants');
const config = require('../config/environment');

function authenticateToken(req, res, next) {
    const authHeader = req.header('Authorization');
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ message: 'Acceso denegado' });
    }

    try {
        const verified = jwt.verify(token, config.secretKey);
        req.user = verified;
        next();
    } catch (err) {
        if (err.name === 'JsonWebTokenError') {
            return res.status(400).json({ message: 'Token no válido' });
        } else {
            console.error('Error inesperado:', err);
            return res.status(500).json({ message: 'Error del servidor' });
        }
    }
}

function checkRole(role) {
    return (req, res, next) => {
        if (!req.user) {
            return res.status(401).json({ message: 'No autenticado' });
        }

        if (req.user.role !== role && req.user.role !== ROLES.ADMIN) {
            return res.status(403).json({ message: 'No autorizado para este recurso' });
        }

        next();
    };
}

module.exports = {
    authenticateToken,
    checkRole
};