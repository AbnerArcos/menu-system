-- ================================================
-- Menu System — Ejecuta esto en phpMyAdmin o MySQL
-- ================================================

CREATE DATABASE IF NOT EXISTS menu_system CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE menu_system;

CREATE TABLE IF NOT EXISTS users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(100) NOT NULL,
  email VARCHAR(150) NOT NULL UNIQUE,
  password VARCHAR(255) NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS menus (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  layout TINYINT NOT NULL DEFAULT 1 COMMENT '1=Lista, 2=Grid',
  slug VARCHAR(100) NOT NULL UNIQUE COMMENT 'URL pública: /ver/slug',
  data LONGTEXT NOT NULL COMMENT 'JSON con toda la config del menú',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  INDEX idx_user (user_id),
  INDEX idx_slug (slug)
);
