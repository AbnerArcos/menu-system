# 🍽️ Sistema de Menú Digital — Instrucciones de instalación

## Estructura de archivos

```
menu-system/
├── index.php          ← App principal (login + dashboard + editor)
├── ver.php            ← Vista pública del menú (para clientes)
├── config.php         ← Configuración de BD y helpers
├── setup.sql          ← Script para crear la base de datos
├── api/
│   ├── auth.php       ← API de registro y login
│   └── menus.php      ← API para guardar/cargar/listar menús
└── README.md
```

## Pasos de instalación

### 1. Crear la base de datos (phpMyAdmin)

1. Entra a tu **cPanel → phpMyAdmin**
2. Haz clic en **"Nueva"** para crear una base de datos
3. Ponle el nombre: `menu_system`
4. Selecciona la base de datos recién creada
5. Ve a la pestaña **"SQL"**
6. Copia y pega el contenido de `setup.sql` y ejecuta

### 2. Editar config.php

Abre `config.php` y actualiza:

```php
define('DB_HOST', 'localhost');       // casi siempre es localhost
define('DB_NAME', 'menu_system');     // nombre de tu base de datos
define('DB_USER', 'tu_usuario');      // usuario de MySQL en cPanel
define('DB_PASS', 'tu_contraseña');   // contraseña del usuario MySQL
define('APP_URL', 'https://tudominio.com/menu-system');  // URL de tu carpeta
define('COOKIE_SECURE', true);        // true si tienes HTTPS (recomendado)
```

> En Hostinger/cPanel el usuario MySQL suele ser algo como `nombreusuario_menu`

### 3. Subir archivos al hosting

Usando **Administrador de archivos** en cPanel o **FTP (FileZilla)**:

1. Sube toda la carpeta `menu-system/` a la raíz de tu dominio o en una subcarpeta
2. Ejemplo: `public_html/menu-system/`
3. Asegúrate de que la estructura sea exactamente como la mostrada arriba

### 4. Verificar permisos

- Carpeta raíz `menu-system/`: **755**
- Carpeta `api/`: **755**
- Archivos `.php`: **644**

### 5. Acceder al sistema

- **Panel de administración**: `https://tudominio.com/menu-system/`
- **Ver menú público**: `https://tudominio.com/menu-system/ver.php?slug=nombre-del-menu`

---

## Cómo funciona

1. El usuario entra a `index.php` → si no está logueado, ve pantalla de Login/Registro
2. Tras autenticarse, ve el **Dashboard** con sus menús guardados
3. Puede **crear nuevo menú** eligiendo Layout 1 (lista) o Layout 2 (grid)
4. El editor tiene **autoguardado** — guarda automáticamente 1.5s después de cualquier cambio
5. Cada menú genera una **URL pública única** (`ver.php?slug=nombre`) que puedes compartir con clientes
6. Los clientes ven el menú, agregan al carrito y envían el pedido por **WhatsApp**

---

## Requisitos del hosting

- PHP 7.4 o superior (con extensiones `pdo`, `pdo_mysql`)
- MySQL 5.7 o superior
- Conexión a internet (para cargar fuentes de Google Fonts en el menú público)

---

## ¿Problemas comunes?

| Error | Solución |
|-------|----------|
| "Error de conexión a BD" | Verifica las credenciales en `config.php` |
| Página en blanco | Activa `display_errors` en PHP o revisa el log de errores de cPanel |
| "No autenticado" en las APIs | Verifica que `session_start()` funcione correctamente en tu hosting |
| Imágenes muy pesadas | Las imágenes se guardan como base64 en la BD; usa fotos bajo 3MB |
