function errorHandler(err, req, res, next) {
    console.error(err);
    
    // Manejar errores específicos
    if (err.name === 'UnauthorizedError') {
        return res.status(401).json({ message: 'Token no válido' });
    }

    if (err.name === 'ValidationError') {
        return res.status(400).json({ message: err.message });
    }

    // Error genérico del servidor
    res.status(500).json({ 
        message: 'Error interno del servidor',
        error: process.env.NODE_ENV === 'development' ? err.message : undefined
    });
}

module.exports = errorHandler;