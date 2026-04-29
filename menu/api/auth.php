<?php
// api/auth.php — Registro y Login
require_once __DIR__ . '/../config.php';

header('Content-Type: application/json');
$action = $_GET['action'] ?? '';

// ── REGISTRO ──────────────────────────────────
if ($action === 'register' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    $body = json_decode(file_get_contents('php://input'), true);
    $name  = trim($body['name']  ?? '');
    $email = trim($body['email'] ?? '');
    $pass  = $body['password']   ?? '';

    if (!$name || !$email || !$pass)
        jsonResponse(['error' => 'Todos los campos son requeridos'], 400);

    if (!filter_var($email, FILTER_VALIDATE_EMAIL))
        jsonResponse(['error' => 'Email inválido'], 400);

    if (strlen($pass) < 6)
        jsonResponse(['error' => 'La contraseña debe tener al menos 6 caracteres'], 400);

    $db = getDB();
    $st = $db->prepare('SELECT id FROM users WHERE email = ?');
    $st->execute([$email]);
    if ($st->fetch())
        jsonResponse(['error' => 'Ese email ya está registrado'], 409);

    $hash = password_hash($pass, PASSWORD_BCRYPT);
    $ins  = $db->prepare('INSERT INTO users (name, email, password) VALUES (?, ?, ?)');
    $ins->execute([$name, $email, $hash]);
    $userId = (int)$db->lastInsertId();

    startSession();
    $_SESSION['user_id']   = $userId;
    $_SESSION['user_name'] = $name;

    jsonResponse(['ok' => true, 'name' => $name, 'user_id' => $userId]);
}

// ── LOGIN ─────────────────────────────────────
if ($action === 'login' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    $body  = json_decode(file_get_contents('php://input'), true);
    $email = trim($body['email']    ?? '');
    $pass  = $body['password']      ?? '';

    if (!$email || !$pass)
        jsonResponse(['error' => 'Email y contraseña requeridos'], 400);

    $db = getDB();
    $st = $db->prepare('SELECT id, name, password FROM users WHERE email = ?');
    $st->execute([$email]);
    $user = $st->fetch();

    if (!$user || !password_verify($pass, $user['password']))
        jsonResponse(['error' => 'Credenciales incorrectas'], 401);

    startSession();
    $_SESSION['user_id']   = (int)$user['id'];
    $_SESSION['user_name'] = $user['name'];

    jsonResponse(['ok' => true, 'name' => $user['name'], 'user_id' => (int)$user['id']]);
}

// ── LOGOUT ────────────────────────────────────
if ($action === 'logout') {
    startSession();
    session_destroy();
    jsonResponse(['ok' => true]);
}

// ── WHOAMI ────────────────────────────────────
if ($action === 'whoami') {
    startSession();
    if (!empty($_SESSION['user_id']))
        jsonResponse(['logged' => true, 'name' => $_SESSION['user_name'], 'user_id' => $_SESSION['user_id']]);
    else
        jsonResponse(['logged' => false]);
}

jsonResponse(['error' => 'Acción no válida'], 404);
