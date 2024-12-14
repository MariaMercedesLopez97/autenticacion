# Sistema de Autenticación

## 🔐 Descripción del Proyecto
Este es un sistema de autenticación robusto desarrollado con Node.js, Express y PostgreSQL, que ofrece mecanismos seguros de registro de usuarios, inicio de sesión y autorización.

## ✨ Características
- Registro de Usuarios
- Inicio de Sesión Seguro
- Hash de Contraseñas
- Autenticación basada en JWT
- Limitación de Tasa de Solicitudes
- Protección CSRF
- Encabezados de Seguridad

## 🛠 Tecnologías Utilizadas
- **Backend**: Node.js, Express
- **Base de Datos**: PostgreSQL
- **Autenticación**: 
  - Tokens Web JSON (JWT)
  - Bcrypt para hash de contraseñas
- **Seguridad**: 
  - Helmet
  - Límite de Tasa de Express
  - CSURF

## 📦 Requisitos Previos
- Node.js (v14+ recomendado)
- PostgreSQL
- npm

## 🚀 Instalación

1. Clonar el repositorio
```bash
git clone https://tu-url-de-repositorio.git
cd proyecto-autenticacion
```

2. Instalar dependencias
```bash
npm install
```

3. Configurar variables de entorno
- Crear un archivo `.env` en el directorio raíz
- Añadir las siguientes variables:
  ```
  DB_HOST=tu_host_de_base_de_datos
  DB_USER=tu_usuario_de_base_de_datos
  DB_PASSWORD=tu_contraseña_de_base_de_datos
  DB_NAME=tu_nombre_de_base_de_datos
  JWT_SECRET=tu_secreto_jwt
  ```

4. Iniciar el servidor
```bash
# Modo de desarrollo
npm run dev

# Modo de producción
npm start
```

## 🔒 Características de Seguridad
- Contraseñas hasheadas usando bcrypt
- JWT para autenticación segura
- Limitación de tasa para prevenir ataques de fuerza bruta
- Protección CSRF
- Encabezados HTTP seguros

## 📝 Configuración del Entorno
Asegúrate de configurar correctamente todas las variables de entorno en `.env` para la conexión a la base de datos y el secreto JWT.

## 🤝 Contribución
1. Haz un fork del repositorio
2. Crea tu rama de características (`git checkout -b caracteristica/FantasticaCaracteristica`)
3. Confirma tus cambios (`git commit -m 'Agregar alguna FantasticaCaracteristica'`)
4. Sube a la rama (`git push origin caracteristica/FantasticaCaracteristica`)
5. Abre un Pull Request


