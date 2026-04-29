<?php
// api/menus.php — Guardar, cargar y listar menús
require_once __DIR__ . '/../config.php';

header('Content-Type: application/json');

$userId = currentUser();
if (!$userId) jsonResponse(['error' => 'No autenticado'], 401);

$action = $_GET['action'] ?? '';

// ── LISTAR menús del usuario ──────────────────
if ($action === 'list' && $_SERVER['REQUEST_METHOD'] === 'GET') {
    $db = getDB();
    $st = $db->prepare(
        'SELECT id, layout, slug, JSON_UNQUOTE(JSON_EXTRACT(data,"$.name")) AS name,
                updated_at FROM menus WHERE user_id = ? ORDER BY updated_at DESC'
    );
    $st->execute([$userId]);
    jsonResponse(['menus' => $st->fetchAll()]);
}

// ── GUARDAR (crear o actualizar) ─────────────
if ($action === 'save' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    $body   = json_decode(file_get_contents('php://input'), true);
    $layout = (int)($body['layout'] ?? 1);
    $data   = $body['data'] ?? null;
    $menuId = (int)($body['menu_id'] ?? 0);

    if (!$data || !in_array($layout, [1, 2]))
        jsonResponse(['error' => 'Datos inválidos'], 400);

    $dataJson = json_encode($data);
    $db = getDB();

    if ($menuId > 0) {
        // Actualizar solo si pertenece al usuario
        $st = $db->prepare('SELECT id FROM menus WHERE id = ? AND user_id = ?');
        $st->execute([$menuId, $userId]);
        if (!$st->fetch()) jsonResponse(['error' => 'Menú no encontrado'], 404);

        $db->prepare('UPDATE menus SET layout = ?, data = ? WHERE id = ?')
           ->execute([$layout, $dataJson, $menuId]);

        jsonResponse(['ok' => true, 'menu_id' => $menuId]);
    } else {
        // Nuevo menú
        $name = $data['name'] ?? 'Mi Menú';
        $slug = makeSlug($name);
        $ins  = $db->prepare(
            'INSERT INTO menus (user_id, layout, slug, data) VALUES (?, ?, ?, ?)'
        );
        $ins->execute([$userId, $layout, $slug, $dataJson]);
        $newId = (int)$db->lastInsertId();
        jsonResponse(['ok' => true, 'menu_id' => $newId, 'slug' => $slug]);
    }
}

// ── CARGAR un menú específico ─────────────────
if ($action === 'load' && $_SERVER['REQUEST_METHOD'] === 'GET') {
    $menuId = (int)($_GET['menu_id'] ?? 0);
    if (!$menuId) jsonResponse(['error' => 'menu_id requerido'], 400);

    $db = getDB();
    $st = $db->prepare('SELECT * FROM menus WHERE id = ? AND user_id = ?');
    $st->execute([$menuId, $userId]);
    $menu = $st->fetch();
    if (!$menu) jsonResponse(['error' => 'Menú no encontrado'], 404);

    $menu['data'] = json_decode($menu['data'], true);
    jsonResponse(['menu' => $menu]);
}

// ── ELIMINAR ──────────────────────────────────
if ($action === 'delete' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    $body   = json_decode(file_get_contents('php://input'), true);
    $menuId = (int)($body['menu_id'] ?? 0);
    if (!$menuId) jsonResponse(['error' => 'menu_id requerido'], 400);

    $db = getDB();
    $st = $db->prepare('DELETE FROM menus WHERE id = ? AND user_id = ?');
    $st->execute([$menuId, $userId]);
    if ($st->rowCount() === 0) jsonResponse(['error' => 'No encontrado'], 404);

    jsonResponse(['ok' => true]);
}

jsonResponse(['error' => 'Acción no válida'], 404);
