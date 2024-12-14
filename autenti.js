const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const csrf = require('csurf');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const db = require('./conexionDB/db');

const app = express();

// Input validation functions
function isValidEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
}

function isValidPassword(password) {
    // Aplicar complejidad a la contraseña (mínimo 8 caracteres, una letra mayúscula, un número)
    const passwordRegex = /^(?=.*[A-Z])(?=.*\d)[A-Za-z\d]{8,}$/;
    return passwordRegex.test(password);
}

// Middleware globales
app.use(express.json());
app.use(helmet());
app.use(cookieParser());

const csrfProtection = csrf({
    cookie: {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
    },
});
app.use(csrfProtection);

// Limitación de velocidad para intentos de inicio de sesión
const loginLimiter = rateLimit({
    windowMs: 1 * 60 * 1000, // 1 minutes
    max: 5, // limit each IP to 5 login attempts
    message: 'Demasiados intentos de inicio de sesión, por favor intente más tarde'
});

// Generar el token CSRF
app.get('/csrf-token', (req, res) => {
    res.json({ csrfToken: req.csrfToken() });
});

const secretKey = process.env.JWT_SECRET || 'kerberos';

// Roles disponibles
const ROLES = {
    USER: 'user',
    ADMIN: 'admin'
};

// Middleware para verificar JWT y roles
function authenticateToken(req, res, next) {
    const authHeader = req.header('Authorization');
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ message: 'Acceso denegado' });
    }

    try {
        const verified = jwt.verify(token, secretKey);
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

// Middleware para verificar rol
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

// Ruta para registrar usuarios
app.post('/register', async (req, res) => {
    const { email, password, role = ROLES.USER } = req.body;

    // Validar campos
    if (!email || !password) {
        return res.status(400).json({ message: 'Todos los campos deben ser completados' });
    }

    // Sanitize and validate email
    const sanitizedEmail = email.trim().toLowerCase();
    if (!isValidEmail(sanitizedEmail)) {
        return res.status(400).json({ message: 'Email inválido' });
    }

    // Validate password complexity
    if (!isValidPassword(password)) {
        return res.status(400).json({ message: 'La contraseña no cumple los requisitos de seguridad' });
    }

    // Add input length limits
    if (sanitizedEmail.length > 255 || password.length > 72) {
        return res.status(400).json({ message: 'Longitud de entrada excesiva' });
    }

    // Validar que solo los administradores puedan crear otros administradores
    if (role === ROLES.ADMIN) {
        const authHeader = req.header('Authorization');
        if (!authHeader) {
            return res.status(403).json({ message: 'No autorizado para crear administradores' });
        }

        try {
            const token = authHeader.split(' ')[1];
            const decoded = jwt.verify(token, secretKey);
            if (decoded.role !== ROLES.ADMIN) {
                return res.status(403).json({ message: 'Solo los administradores pueden crear otros administradores' });
            }
        } catch (err) {
            return res.status(403).json({ message: 'Token inválido' });
        }
    }

    try {
        // Validar si el email ya está registrado
        const existingUser = await db.query('SELECT * FROM register WHERE email = $1', [sanitizedEmail]);
        if (existingUser.rows.length > 0) {
            return res.status(400).json({ message: `${sanitizedEmail} ya está registrado` });
        }

        // Cifrar la contraseña
        const hashedPassword = await bcrypt.hash(password, 10);

        // Insertar usuario en la base de datos con rol
        await db.query('INSERT INTO register (email, password, role) VALUES ($1, $2, $3)', 
            [sanitizedEmail, hashedPassword, role]);
        
        res.status(201).json({ message: `Usuario ${sanitizedEmail} registrado exitosamente con rol ${role}` });
    } catch (error) {
        console.error('Error al registrar usuario:', error);
        res.status(500).json({ message: 'Error del servidor' });
    }
});

// Ruta de login
app.post('/login', loginLimiter, async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ message: 'Todos los campos deben ser completados' });
    }

    const sanitizedEmail = email.trim().toLowerCase();

    try {
        // Buscar usuario
        const user = await db.query('SELECT * FROM register WHERE email = $1', [sanitizedEmail]);
        if (user.rows.length === 0) {
            return res.status(400).json({ message: 'Usuario no encontrado' });
        }

        // Verificar la contraseña
        const validPassword = await bcrypt.compare(password, user.rows[0].password);
        if (!validPassword) {
            return res.status(400).json({ message: 'Contraseña incorrecta' });
        }
//--------------------ESTE--------------------------------------------------------------
        // Generar el token JWT incluyendo el rol
        const token = jwt.sign(
            { 
                userId: user.rows[0].id,
                role: user.rows[0].role 
            }, 
            secretKey, 
            { expiresIn: '1h' }
        );
//--------------------------------------------------------------------------------------
        res.json({ token, role: user.rows[0].role });
    } catch (error) {
        console.error('Error en login:', error);
        res.status(500).json({ message: 'Error del servidor' });
    }
});

// Ruta protegida: Obtener usuarios (solo admin)
app.get('/users', authenticateToken, checkRole(ROLES.ADMIN), async (req, res) => {
    try {
        const result = await db.query('SELECT id, email, role FROM register');
        res.status(200).json(result.rows);
    } catch (error) {
        console.error('Error al obtener usuarios:', error);
        res.status(500).json({ message: 'Error del servidor' });
    }
});

// Ruta protegida: Actualizar rol de usuario (solo admin)
app.put('/users/:id/role', authenticateToken, checkRole(ROLES.ADMIN), async (req, res) => {
    const { id } = req.params;
    const { role } = req.body;

    if (!Object.values(ROLES).includes(role)) {
        return res.status(400).json({ message: 'Rol inválido' });
    }

    try {
        const result = await db.query(
            'UPDATE register SET role = $1 WHERE id = $2 RETURNING id, email, role',
            [role, id]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ message: 'Usuario no encontrado' });
        }

        res.json(result.rows[0]);
    } catch (error) {
        console.error('Error al actualizar rol:', error);
        res.status(500).json({ message: 'Error del servidor' });
    }
});

// Generic error handler
app.use((err, req, res, next) => {
    console.error(err);
    res.status(500).json({ message: 'Error interno del servidor' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Servidor corriendo en el puerto ${PORT}`);
});