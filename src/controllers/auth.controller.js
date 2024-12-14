const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const UserModel = require('../models/user.model');
const { ROLES } = require('../utils/constants');

const secretKey = process.env.JWT_SECRET || 'kerberos';

class AuthController {
    static async register(req, res) {
        const { password, role = ROLES.USER } = req.body;
        const sanitizedEmail = req.sanitizedEmail;

        try {
            const existingUser = await UserModel.findByEmail(sanitizedEmail);
            if (existingUser) {
                return res.status(400).json({ message: `${sanitizedEmail} ya está registrado` });
            }

            const hashedPassword = await bcrypt.hash(password, 10);
            const newUser = await UserModel.create(sanitizedEmail, hashedPassword, role);
            
            res.status(201).json({ 
                message: `Usuario ${sanitizedEmail} registrado exitosamente con rol ${role}`,
                userId: newUser.id 
            });
        } catch (error) {
            console.error('Error al registrar usuario:', error);
            res.status(500).json({ message: 'Error del servidor' });
        }
    }

    static async login(req, res) {
        const { email, password } = req.body;

        try {
            const user = await UserModel.findByEmail(email);
            if (!user) {
                return res.status(400).json({ message: 'Usuario no encontrado' });
            }

            const validPassword = await bcrypt.compare(password, user.password);
            if (!validPassword) {
                return res.status(400).json({ message: 'Contraseña incorrecta' });
            }

            const token = jwt.sign(
                { 
                    userId: user.id,
                    role: user.role 
                }, 
                secretKey, 
                { expiresIn: '1h' }
            );

            res.json({ token, role: user.role });
        } catch (error) {
            console.error('Error en login:', error);
            res.status(500).json({ message: 'Error del servidor' });
        }
    }
}

module.exports = AuthController;