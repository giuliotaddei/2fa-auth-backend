CREATE DATABASE IF NOT EXISTS auth2fa_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

USE auth2fa_db;

CREATE TABLE IF NOT EXISTS users (
    id            BIGINT AUTO_INCREMENT PRIMARY KEY,
    email         VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    totp_secret   TEXT,                          -- cifrato con AES-256
    totp_enabled  BOOLEAN NOT NULL DEFAULT FALSE,
    failed_attempts INT NOT NULL DEFAULT 0,
    locked_until  DATETIME,
    created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_login    DATETIME,
    INDEX idx_email (email)
);

CREATE TABLE IF NOT EXISTS refresh_tokens (
    id          BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id     BIGINT NOT NULL,
    token_hash  VARCHAR(255) NOT NULL UNIQUE,    -- hash del token, non il token in chiaro
    expires_at  DATETIME NOT NULL,
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_refresh_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_token_hash (token_hash),
    INDEX idx_user_id (user_id)
);