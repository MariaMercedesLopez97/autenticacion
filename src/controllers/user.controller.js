const UserModel = require('../models/user.model');
const { ROLES } = require('../utils/constants');

class UserController {
    static async getAllUsers(req, res) {
        try {
            const users = await UserModel.getAllUsers();
            res.status(200).json(users);
        } catch (error) {
            console.error('Error al obtener usuarios:', error);
            res.status(500).json({ message: 'Error del servidor' });
        }
    }

    static async updateUserRole(req, res) {
        const { id } = req.params;
        const { role } = req.body;

        if (!Object.values(ROLES).includes(role)) {
            return res.status(400).json({ message: 'Rol inválido' });
        }

        try {
            const updatedUser = await UserModel.updateUserRole(id, role);

            if (!updatedUser) {
                return res.status(404).json({ message: 'Usuario no encontrado' });
            }

            res.json(updatedUser);
        } catch (error) {
            console.error('Error al actualizar rol:', error);
            res.status(500).json({ message: 'Error del servidor' });
        }
    }
}

module.exports = UserController;