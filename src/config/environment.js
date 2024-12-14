require('dotenv').config();

const config = {
    port: process.env.PORT || 3000,
    secretKey: process.env.JWT_SECRET || 'kerberos',
    nodeEnv: process.env.NODE_ENV || 'development'
};

module.exports = config;