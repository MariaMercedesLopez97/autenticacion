const db = require('../config/database');
const { ROLES } = require('../utils/constants');

class UserModel {
    static async findByEmail(email) {
        const result = await db.query('SELECT * FROM register WHERE email = $1', [email]);
        return result.rows[0];
    }

    static async create(email, hashedPassword, role = ROLES.USER) {
        const result = await db.query(
            'INSERT INTO register (email, password, role) VALUES ($1, $2, $3) RETURNING *', 
            [email, hashedPassword, role]
        );
        return result.rows[0];
    }

    static async getAllUsers() {
        const result = await db.query('SELECT id, email, role FROM register');
        return result.rows;
    }

    static async updateUserRole(id, role) {
        const result = await db.query(
            'UPDATE register SET role = $1 WHERE id = $2 RETURNING id, email, role',
            [role, id]
        );
        return result.rows[0];
    }
}

module.exports = UserModel;