const express = require('express');
const UserController = require('../controllers/user.controller');
const { authenticateToken, checkRole } = require('../middleware/auth.middleware');
const { ROLES } = require('../utils/constants');

const router = express.Router();

router.get('/', authenticateToken, UserController.getAllUsers);
router.put('/:id/role', authenticateToken, checkRole(ROLES.ADMIN), UserController.updateUserRole);

module.exports = router;