<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Editor de Menú Digital</title>
<style>
*{margin:0;padding:0;box-sizing:border-box;font-family:'Segoe UI',sans-serif}
:root{
  --brand:#b58b63;--brand-dark:#a1764f;--bg:#f5f2ee;--white:#fff;
  --gray:#f1ede8;--text:#1a1a1a;--muted:#777;--border:#e0d8d0;
  --danger:#e53935;--success:#25D366
}
body{background:var(--bg);color:var(--text);min-height:100vh}

/* ── AUTH SCREENS ── */
.auth-wrap{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
.auth-card{background:var(--white);border-radius:22px;padding:36px 32px;width:100%;max-width:400px;box-shadow:0 20px 60px rgba(0,0,0,.1)}
.auth-card h1{font-size:22px;margin-bottom:4px}
.auth-card p{font-size:13px;color:var(--muted);margin-bottom:24px}
.form-group{margin-bottom:14px}
.form-group label{display:block;font-size:11px;font-weight:600;color:var(--muted);margin-bottom:5px;text-transform:uppercase;letter-spacing:.5px}
.form-group input{width:100%;padding:10px 14px;border:1px solid var(--border);border-radius:10px;font-size:14px;outline:none;transition:border .2s;background:var(--gray)}
.form-group input:focus{border-color:var(--brand);background:var(--white)}
.btn-full{width:100%;padding:12px;border:none;border-radius:11px;font-size:14px;font-weight:600;cursor:pointer;transition:all .2s}
.btn-primary{background:var(--brand);color:white}
.btn-primary:hover{background:var(--brand-dark)}
.auth-switch{text-align:center;margin-top:18px;font-size:13px;color:var(--muted)}
.auth-switch a{color:var(--brand);cursor:pointer;font-weight:600;text-decoration:none}
.error-msg{background:#fdecea;color:var(--danger);border-radius:9px;padding:10px 14px;font-size:13px;margin-bottom:14px;display:none}
.error-msg.show{display:block}

/* ── DASHBOARD ── */
.dashboard{min-height:100vh;padding:30px 20px}
.dash-header{display:flex;align-items:center;justify-content:space-between;max-width:900px;margin:0 auto 30px}
.dash-header h1{font-size:20px}
.dash-header span{font-size:13px;color:var(--muted)}
.dash-top{display:flex;align-items:center;gap:12px}
.btn-logout{padding:8px 16px;border:1px solid var(--border);border-radius:9px;background:transparent;font-size:13px;cursor:pointer}
.btn-logout:hover{background:var(--gray)}

.dash-grid{max-width:900px;margin:0 auto}
.dash-section-title{font-size:13px;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:.6px;margin-bottom:14px}

/* Template cards */
.template-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:16px;margin-bottom:32px}
.template-card{background:var(--white);border-radius:18px;overflow:hidden;border:2px solid var(--border);cursor:pointer;transition:all .25s}
.template-card:hover{border-color:var(--brand);transform:translateY(-2px);box-shadow:0 12px 30px rgba(181,139,99,.15)}
.template-card.selected{border-color:var(--brand)}
.template-preview{height:160px;display:flex;align-items:center;justify-content:center;font-size:48px;background:var(--gray)}
.template-info{padding:14px 16px}
.template-info h3{font-size:14px;font-weight:600;margin-bottom:3px}
.template-info p{font-size:12px;color:var(--muted)}
.btn-new-menu{display:inline-flex;align-items:center;gap:8px;padding:10px 20px;background:var(--brand);color:white;border:none;border-radius:11px;font-size:14px;font-weight:600;cursor:pointer;margin-bottom:30px}
.btn-new-menu:disabled{opacity:.5;cursor:not-allowed}
.btn-new-menu:not(:disabled):hover{background:var(--brand-dark)}

/* Mis menús */
.my-menus-list{display:grid;gap:10px;margin-bottom:30px}
.menu-row{background:var(--white);border-radius:14px;padding:14px 18px;display:flex;align-items:center;gap:14px;border:1px solid var(--border)}
.menu-row-icon{width:44px;height:44px;border-radius:12px;background:var(--gray);display:flex;align-items:center;justify-content:center;font-size:20px;flex-shrink:0}
.menu-row-info{flex:1;min-width:0}
.menu-row-info h3{font-size:14px;font-weight:600;margin-bottom:2px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.menu-row-info p{font-size:11px;color:var(--muted)}
.menu-row-actions{display:flex;gap:8px;flex-shrink:0}
.btn-sm{padding:7px 12px;border-radius:8px;border:none;font-size:12px;font-weight:600;cursor:pointer}
.btn-edit{background:var(--brand);color:white}
.btn-edit:hover{background:var(--brand-dark)}
.btn-view{background:var(--gray);color:var(--text);border:1px solid var(--border)}
.btn-view:hover{background:var(--border)}
.btn-delete{background:#fdecea;color:var(--danger);border:1px solid #fca5a5}
.btn-delete:hover{background:#e53935;color:white}
.badge-layout{display:inline-flex;padding:2px 8px;border-radius:6px;font-size:10px;font-weight:600;background:#e8f0fe;color:#1a56db;margin-left:6px}
.no-menus{text-align:center;padding:30px;color:var(--muted);font-size:14px}

/* ── EDITOR LAYOUT ── */
.editor-wrap{display:none}
.editor-layout{display:grid;grid-template-columns:390px 1fr;min-height:100vh}
.panel-left{background:var(--white);border-right:1px solid var(--border);display:flex;flex-direction:column;position:sticky;top:0;height:100vh;overflow:hidden}
.panel-right{background:var(--bg);padding:20px;display:flex;flex-direction:column;align-items:center}
.panel-header{padding:14px 20px;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:10px}
.panel-header-info{flex:1}
.panel-header h1{font-size:15px;font-weight:600;margin-bottom:1px}
.panel-header p{font-size:11px;color:var(--muted)}
.btn-back{padding:6px 12px;border:1px solid var(--border);border-radius:8px;font-size:12px;font-weight:600;background:transparent;cursor:pointer}
.btn-back:hover{background:var(--gray)}
.panel-tabs{display:flex;border-bottom:1px solid var(--border)}
.ptab{flex:1;padding:10px 4px;border:none;background:transparent;font-size:11px;font-weight:500;color:var(--muted);cursor:pointer;border-bottom:2px solid transparent}
.ptab.active{color:var(--brand);border-bottom-color:var(--brand)}
.panel-body{flex:1;overflow-y:auto;padding:14px 18px}
.tab-content{display:none}
.tab-content.active{display:block}
.form-group-ed{margin-bottom:12px}
.form-group-ed label{display:block;font-size:11px;font-weight:600;color:var(--muted);margin-bottom:4px;text-transform:uppercase;letter-spacing:.5px}
.form-group-ed input,.form-group-ed textarea,.form-group-ed select{width:100%;padding:8px 11px;border:1px solid var(--border);border-radius:9px;font-size:13px;color:var(--text);background:var(--gray);outline:none;transition:border .2s}
.form-group-ed input:focus,.form-group-ed textarea:focus{border-color:var(--brand);background:var(--white)}
.form-group-ed textarea{resize:vertical;min-height:52px}
.color-row{display:flex;align-items:center;gap:8px}
.color-row input[type="color"]{width:40px;height:34px;border-radius:8px;border:1px solid var(--border);cursor:pointer;padding:2px}
.section-card{background:var(--gray);border-radius:14px;padding:12px;margin-bottom:10px;border:1px solid var(--border)}
.section-card-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:10px}
.section-card-header h3{font-size:13px;font-weight:600}
.btn-icon{width:26px;height:26px;border-radius:7px;border:none;background:transparent;cursor:pointer;display:flex;align-items:center;justify-content:center;font-size:13px;color:var(--muted)}
.btn-icon:hover{background:var(--border)}
.btn-icon.danger:hover{background:#fdecea;color:var(--danger)}
.product-card{background:var(--white);border-radius:12px;padding:11px;margin-bottom:9px;border:1px solid var(--border)}
.product-card-header{display:flex;align-items:center;gap:8px;margin-bottom:8px}
.product-card .form-group-ed{margin-bottom:7px}
.product-card .form-group-ed label{font-size:10px}
.product-card .form-group-ed input{font-size:12px;padding:7px 10px}
.product-row{display:grid;grid-template-columns:1fr 1fr;gap:8px}
.add-product-btn{width:100%;padding:8px;border:2px dashed var(--border);border-radius:9px;background:transparent;color:var(--brand);font-size:12px;font-weight:600;cursor:pointer}
.add-product-btn:hover{border-color:var(--brand);background:#fdf7f2}
.btn-add-section{width:100%;padding:9px;border:2px dashed var(--brand);border-radius:11px;background:transparent;color:var(--brand);font-size:13px;font-weight:600;cursor:pointer;margin-top:6px}
.btn-add-section:hover{background:#fdf7f2}
.download-bar{padding:12px 18px;border-top:1px solid var(--border);background:var(--white);display:flex;flex-direction:column;gap:7px}
.preview-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:14px;width:380px}
.preview-label{font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.8px;color:var(--muted)}
.phone-frame{background:#1a1a1a;border-radius:44px;padding:10px;box-shadow:0 30px 80px rgba(0,0,0,.35);width:380px}
.phone-screen{border-radius:36px;overflow:hidden;height:720px;background:#f9f7f4}
.phone-screen iframe{width:100%;height:100%;border:none;display:block}
.badge{display:inline-flex;align-items:center;padding:2px 8px;border-radius:6px;font-size:11px;font-weight:500}
.badge-success{background:#e8f8f0;color:#1a7a40}
.badge-warn{background:#fff3e0;color:#e65100}
.img-upload-box{border:2px dashed var(--border);border-radius:10px;cursor:pointer;background:var(--gray);overflow:hidden;position:relative;min-height:80px}
.img-upload-box:hover{border-color:var(--brand)}
.img-upload-box input[type="file"]{position:absolute;inset:0;opacity:0;cursor:pointer;z-index:2;width:100%;height:100%}
.img-upload-placeholder{display:flex;flex-direction:column;align-items:center;justify-content:center;padding:14px 10px;gap:3px;pointer-events:none}
.img-upload-placeholder .icon{font-size:20px}
.img-upload-placeholder .label{font-size:11px;color:var(--muted);text-align:center;line-height:1.3}
.img-upload-preview{width:100%;height:80px;object-fit:cover;display:block}
.img-upload-clear{position:absolute;top:4px;right:4px;width:20px;height:20px;border-radius:50%;border:none;background:rgba(0,0,0,.55);color:white;font-size:11px;cursor:pointer;display:flex;align-items:center;justify-content:center;z-index:3}
.img-upload-loading{position:absolute;inset:0;background:rgba(255,255,255,.85);display:flex;align-items:center;justify-content:center;font-size:11px;color:var(--muted);z-index:4}
.thumb-placeholder{width:44px;height:44px;border-radius:10px;background:var(--border);display:flex;align-items:center;justify-content:center;font-size:18px;flex-shrink:0}
.save-indicator{font-size:11px;color:var(--muted);display:flex;align-items:center;gap:6px}
.save-indicator.saving{color:var(--brand)}
.save-indicator.saved{color:#1a7a40}
.url-box{background:var(--gray);border:1px solid var(--border);border-radius:9px;padding:8px 12px;font-size:11px;color:var(--muted);word-break:break-all;margin-top:6px}
.url-box a{color:var(--brand);text-decoration:none}
.url-box a:hover{text-decoration:underline}
.spinner{width:14px;height:14px;border:2px solid var(--border);border-top-color:var(--brand);border-radius:50%;animation:spin .6s linear infinite;display:inline-block}
@keyframes spin{to{transform:rotate(360deg)}}
</style>
</head>
<body>

<!-- ════════════════════════════════════
     PANTALLA LOGIN
═══════════════════════════════════════ -->
<div id="screen-login" class="auth-wrap">
  <div class="auth-card">
    <h1>🍽️ Menú Digital</h1>
    <p>Inicia sesión para gestionar tus menús</p>
    <div class="error-msg" id="login-error"></div>
    <div class="form-group">
      <label>Correo electrónico</label>
      <input type="email" id="login-email" placeholder="tu@email.com">
    </div>
    <div class="form-group">
      <label>Contraseña</label>
      <input type="password" id="login-pass" placeholder="••••••••">
    </div>
    <button class="btn-full btn-primary" onclick="doLogin()">Entrar</button>
    <p class="auth-switch">¿No tienes cuenta? <a onclick="showScreen('register')">Regístrate gratis</a></p>
  </div>
</div>

<!-- ════════════════════════════════════
     PANTALLA REGISTRO
═══════════════════════════════════════ -->
<div id="screen-register" class="auth-wrap" style="display:none">
  <div class="auth-card">
    <h1>🍽️ Crear cuenta</h1>
    <p>Empieza a crear tu menú digital en minutos</p>
    <div class="error-msg" id="reg-error"></div>
    <div class="form-group">
      <label>Tu nombre</label>
      <input type="text" id="reg-name" placeholder="Nombre del restaurante o tuyo">
    </div>
    <div class="form-group">
      <label>Correo electrónico</label>
      <input type="email" id="reg-email" placeholder="tu@email.com">
    </div>
    <div class="form-group">
      <label>Contraseña</label>
      <input type="password" id="reg-pass" placeholder="Mínimo 6 caracteres">
    </div>
    <button class="btn-full btn-primary" onclick="doRegister()">Crear cuenta</button>
    <p class="auth-switch">¿Ya tienes cuenta? <a onclick="showScreen('login')">Inicia sesión</a></p>
  </div>
</div>

<!-- ════════════════════════════════════
     DASHBOARD
═══════════════════════════════════════ -->
<div id="screen-dashboard" class="dashboard" style="display:none">
  <div class="dash-header">
    <h1>🍽️ Mis Menús</h1>
    <div class="dash-top">
      <span>Hola, <strong id="user-name-display"></strong></span>
      <button class="btn-logout" onclick="doLogout()">Cerrar sesión</button>
    </div>
  </div>
  <div class="dash-grid">
    <p class="dash-section-title">Crear nuevo menú — elige un layout</p>
    <div class="template-grid">
      <div class="template-card" id="tpl-1" onclick="selectTemplate(1)">
        <div class="template-preview">📋</div>
        <div class="template-info">
          <h3>Layout 1 — Lista</h3>
          <p>Imagen + nombre + precio en fila horizontal. Ideal para menús con muchos productos.</p>
        </div>
      </div>
      <div class="template-card" id="tpl-2" onclick="selectTemplate(2)">
        <div class="template-preview">🔲</div>
        <div class="template-info">
          <h3>Layout 2 — Grid</h3>
          <p>Tarjetas en cuadrícula de 2 columnas. Más visual, ideal para postres y bebidas.</p>
        </div>
      </div>
    </div>
    <button class="btn-new-menu" id="btn-new" onclick="startNewMenu()" disabled>
      + Crear nuevo menú
    </button>

    <p class="dash-section-title">Mis menús guardados</p>
    <div class="my-menus-list" id="my-menus-list">
      <div class="no-menus">Cargando...</div>
    </div>
  </div>
</div>

<!-- ════════════════════════════════════
     EDITOR (se inyecta dinámicamente)
═══════════════════════════════════════ -->
<div id="screen-editor" style="display:none"></div>

<script>
// ════════════════════════════════════
// CONFIG — ajusta la URL base
// ════════════════════════════════════
const API_BASE = './api';
const APP_BASE = window.location.origin + window.location.pathname.replace(/\/[^/]*$/, '');

let currentUser = null;
let selectedTemplate = 0;
let currentMenuId = null;
let menuData = {};
let saveTimeout = null;

// ── Utilidades ────────────────────────────────────────────────
function showScreen(name) {
  ['login','register','dashboard','editor'].forEach(s => {
    document.getElementById('screen-'+s).style.display = s === name ? (s === 'editor' ? 'block' : (s === 'dashboard' ? 'block' : 'flex')) : 'none';
  });
  if (name === 'dashboard') loadMyMenus();
}

function showError(elId, msg) {
  const el = document.getElementById(elId);
  el.textContent = msg;
  el.classList.add('show');
  setTimeout(() => el.classList.remove('show'), 4000);
}

async function apiFetch(url, opts = {}) {
  const res = await fetch(url, { credentials: 'include', ...opts });
  return res.json();
}

// ── AUTH ──────────────────────────────────────────────────────
async function checkAuth() {
  const r = await apiFetch(API_BASE + '/auth.php?action=whoami');
  if (r.logged) {
    currentUser = { id: r.user_id, name: r.name };
    document.getElementById('user-name-display').textContent = r.name;
    showScreen('dashboard');
  } else {
    showScreen('login');
  }
}

async function doLogin() {
  const email = document.getElementById('login-email').value.trim();
  const pass  = document.getElementById('login-pass').value;
  if (!email || !pass) { showError('login-error', 'Completa todos los campos'); return; }
  const r = await apiFetch(API_BASE + '/auth.php?action=login', {
    method: 'POST', headers: {'Content-Type':'application/json'},
    body: JSON.stringify({ email, password: pass })
  });
  if (r.error) { showError('login-error', r.error); return; }
  currentUser = { id: r.user_id, name: r.name };
  document.getElementById('user-name-display').textContent = r.name;
  showScreen('dashboard');
}

async function doRegister() {
  const name  = document.getElementById('reg-name').value.trim();
  const email = document.getElementById('reg-email').value.trim();
  const pass  = document.getElementById('reg-pass').value;
  if (!name || !email || !pass) { showError('reg-error', 'Completa todos los campos'); return; }
  const r = await apiFetch(API_BASE + '/auth.php?action=register', {
    method: 'POST', headers: {'Content-Type':'application/json'},
    body: JSON.stringify({ name, email, password: pass })
  });
  if (r.error) { showError('reg-error', r.error); return; }
  currentUser = { id: r.user_id, name: r.name };
  document.getElementById('user-name-display').textContent = r.name;
  showScreen('dashboard');
}

async function doLogout() {
  await apiFetch(API_BASE + '/auth.php?action=logout');
  currentUser = null;
  showScreen('login');
}

// ── DASHBOARD ─────────────────────────────────────────────────
function selectTemplate(n) {
  selectedTemplate = n;
  document.querySelectorAll('.template-card').forEach(c => c.classList.remove('selected'));
  document.getElementById('tpl-'+n).classList.add('selected');
  document.getElementById('btn-new').disabled = false;
}

function startNewMenu() {
  if (!selectedTemplate) return;
  currentMenuId = null;
  menuData = defaultMenuData(selectedTemplate);
  openEditor(selectedTemplate);
}

async function loadMyMenus() {
  const list = document.getElementById('my-menus-list');
  list.innerHTML = '<div class="no-menus"><div class="spinner"></div></div>';
  const r = await apiFetch(API_BASE + '/menus.php?action=list');
  if (!r.menus || r.menus.length === 0) {
    list.innerHTML = '<div class="no-menus">Aún no tienes menús guardados. ¡Crea el primero!</div>';
    return;
  }
  list.innerHTML = r.menus.map(m => `
    <div class="menu-row">
      <div class="menu-row-icon">${m.layout == 2 ? '🔲' : '📋'}</div>
      <div class="menu-row-info">
        <h3>${escH(m.name || 'Sin nombre')} <span class="badge-layout">Layout ${m.layout}</span></h3>
        <p>Actualizado: ${new Date(m.updated_at).toLocaleDateString('es-MX')} · <a href="ver.php?slug=${escH(m.slug)}" target="_blank" style="color:var(--brand)">Ver menú público</a></p>
      </div>
      <div class="menu-row-actions">
        <button class="btn-sm btn-edit" onclick="editMenu(${m.id},${m.layout})">✏️ Editar</button>
        <button class="btn-sm btn-delete" onclick="deleteMenu(${m.id})">🗑</button>
      </div>
    </div>`).join('');
}

async function editMenu(menuId, layout) {
  const r = await apiFetch(`${API_BASE}/menus.php?action=load&menu_id=${menuId}`);
  if (r.error) { alert(r.error); return; }
  currentMenuId = menuId;
  menuData = r.menu.data;
  openEditor(layout);
}

async function deleteMenu(menuId) {
  if (!confirm('¿Eliminar este menú? Esta acción no se puede deshacer.')) return;
  const r = await apiFetch(API_BASE + '/menus.php?action=delete', {
    method: 'POST', headers: {'Content-Type':'application/json'},
    body: JSON.stringify({ menu_id: menuId })
  });
  if (r.ok) loadMyMenus(); else alert(r.error || 'Error al eliminar');
}

function escH(s) {
  return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

// ── DEFAULT DATA ──────────────────────────────────────────────
function defaultMenuData(layout) {
  const base = {
    name:"Mi Restaurante", emoji:"🍽️", welcome:"", currency:"MXN",
    waPhone:"521234567890", waBtnText:"Enviar pedido por WhatsApp",
    waPrefix:"Hola, quiero hacer el siguiente pedido:", waSuccess:"✅ Pedido enviado correctamente",
    colorPrimary:"#b58b63", colorBg:"#f9f7f4", colorOuter:"#e9e4de",
    fontFamily:"Poppins",
    sections:[
      {id:"sec1",name:"Entradas",h2:"Entradas",products:[
        {id:"p1",name:"Producto 1",price:"50",description:"Descripción del producto",image:""},
        {id:"p2",name:"Producto 2",price:"60",description:"Descripción del producto",image:""}
      ]},
      {id:"sec2",name:"Principales",h2:"Platos Principales",products:[
        {id:"p3",name:"Producto 3",price:"120",description:"Descripción del producto",image:""}
      ]}
    ]
  };
  if (layout === 1) { base.borderRadius = "22px"; }
  if (layout === 2) { base.gridCols = "2"; base.cardRadius = "22px"; base.btnStyle = "full"; }
  return base;
}

// ── SAVE TO SERVER ────────────────────────────────────────────
async function saveMenu() {
  setSaveIndicator('saving');
  const r = await apiFetch(API_BASE + '/menus.php?action=save', {
    method: 'POST', headers: {'Content-Type':'application/json'},
    body: JSON.stringify({ layout: currentLayout, data: menuData, menu_id: currentMenuId || 0 })
  });
  if (r.ok) {
    if (!currentMenuId) {
      currentMenuId = r.menu_id;
      updateSlugDisplay(r.slug);
    }
    setSaveIndicator('saved');
  } else {
    setSaveIndicator('');
    alert(r.error || 'Error al guardar');
  }
}

function scheduleSave() {
  clearTimeout(saveTimeout);
  setSaveIndicator('saving');
  saveTimeout = setTimeout(saveMenu, 1500);
}

function setSaveIndicator(state) {
  const el = document.getElementById('save-indicator');
  if (!el) return;
  if (state === 'saving') { el.className='save-indicator saving'; el.innerHTML='<div class="spinner"></div> Guardando...'; }
  else if (state === 'saved') { el.className='save-indicator saved'; el.innerHTML='✅ Guardado'; }
  else { el.className='save-indicator'; el.innerHTML=''; }
}

function updateSlugDisplay(slug) {
  const el = document.getElementById('slug-display');
  if (!el) return;
  const url = APP_BASE + '/ver.php?slug=' + slug;
  el.innerHTML = `URL pública: <a href="${url}" target="_blank">${url}</a>`;
}

// ══════════════════════════════════════════════════════════════
// EDITOR
// ══════════════════════════════════════════════════════════════
let currentLayout = 1;
let previewTimer;

function openEditor(layout) {
  currentLayout = layout;
  const wrap = document.getElementById('screen-editor');
  wrap.innerHTML = buildEditorHTML(layout);
  showScreen('editor');
  renderSectionsEditor();
  updatePreview();
}

function buildEditorHTML(layout) {
  const extraGeneral = layout === 2 ? `
    <div class="form-group-ed">
      <label>Columnas de productos</label>
      <select id="ed-gridCols" onchange="collectData();scheduleSave();updatePreview()">
        <option value="2" ${menuData.gridCols==='2'?'selected':''}>2 columnas</option>
        <option value="1" ${menuData.gridCols==='1'?'selected':''}>1 columna (lista)</option>
      </select>
    </div>` : '';

  const extraStyle = layout === 1 ? `
    <div class="form-group-ed">
      <label>Radio de bordes</label>
      <select id="ed-borderRadius" onchange="collectData();scheduleSave();updatePreview()">
        <option value="22px" ${menuData.borderRadius==='22px'?'selected':''}>Muy redondeado</option>
        <option value="16px" ${menuData.borderRadius==='16px'?'selected':''}>Redondeado</option>
        <option value="8px"  ${menuData.borderRadius==='8px'?'selected':''}>Semi-cuadrado</option>
        <option value="4px"  ${menuData.borderRadius==='4px'?'selected':''}>Cuadrado</option>
      </select>
    </div>` : `
    <div class="form-group-ed">
      <label>Radio de bordes de tarjetas</label>
      <select id="ed-cardRadius" onchange="collectData();scheduleSave();updatePreview()">
        <option value="22px" ${menuData.cardRadius==='22px'?'selected':''}>Muy redondeado</option>
        <option value="14px" ${menuData.cardRadius==='14px'?'selected':''}>Redondeado</option>
        <option value="8px"  ${menuData.cardRadius==='8px'?'selected':''}>Semi-cuadrado</option>
        <option value="4px"  ${menuData.cardRadius==='4px'?'selected':''}>Cuadrado</option>
      </select>
    </div>
    <div class="form-group-ed">
      <label>Estilo del botón agregar</label>
      <select id="ed-btnStyle" onchange="collectData();scheduleSave();updatePreview()">
        <option value="full"    ${menuData.btnStyle==='full'?'selected':''}>Fondo sólido</option>
        <option value="outline" ${menuData.btnStyle==='outline'?'selected':''}>Solo borde</option>
        <option value="round"   ${menuData.btnStyle==='round'?'selected':''}>Círculo +</option>
      </select>
    </div>`;

  const savedSlug = currentMenuId ? '' : '';

  return `
<div class="editor-layout">
  <div class="panel-left">
    <div class="panel-header">
      <button class="btn-back" onclick="goBackToDashboard()">← Mis menús</button>
      <div class="panel-header-info">
        <h1>Editor Layout ${layout}</h1>
        <p id="save-indicator" class="save-indicator">Listo</p>
      </div>
    </div>
    <div class="panel-tabs">
      <button class="ptab active" onclick="switchTab('general',this)">General</button>
      <button class="ptab" onclick="switchTab('secciones',this)">Secciones</button>
      <button class="ptab" onclick="switchTab('whatsapp',this)">WhatsApp</button>
      <button class="ptab" onclick="switchTab('estilo',this)">Estilo</button>
    </div>
    <div class="panel-body">

      <div class="tab-content active" id="tab-general">
        <div class="form-group-ed">
          <label>Nombre del restaurante</label>
          <input type="text" id="ed-name" value="${escH(menuData.name||'')}" oninput="collectData();scheduleSave();updatePreview()">
        </div>
        <div class="form-group-ed">
          <label>Emoji / ícono</label>
          <input type="text" id="ed-emoji" value="${escH(menuData.emoji||'🍽️')}" oninput="collectData();scheduleSave();updatePreview()" maxlength="4">
        </div>
        <div class="form-group-ed">
          <label>Mensaje de bienvenida (opcional)</label>
          <textarea id="ed-welcome" rows="2" oninput="collectData();scheduleSave();updatePreview()">${escH(menuData.welcome||'')}</textarea>
        </div>
        <div class="form-group-ed">
          <label>Moneda</label>
          <select id="ed-currency" onchange="collectData();scheduleSave();updatePreview()">
            ${['MXN','USD','COP','GTQ','PEN','CLP','ARS'].map(c=>`<option value="${c}" ${menuData.currency===c?'selected':''}>${c}</option>`).join('')}
          </select>
        </div>
        ${extraGeneral}
        <div class="form-group-ed" style="margin-top:16px">
          <label>URL pública del menú</label>
          <div class="url-box" id="slug-display">
            ${currentMenuId ? `<a href="ver.php?slug=..." target="_blank">Guarda para ver la URL</a>` : 'Se generará al guardar por primera vez'}
          </div>
        </div>
      </div>

      <div class="tab-content" id="tab-secciones">
        <div id="sections-editor"></div>
        <button class="btn-add-section" onclick="addSection()">+ Agregar sección</button>
      </div>

      <div class="tab-content" id="tab-whatsapp">
        <div class="form-group-ed">
          <label>Número de WhatsApp</label>
          <input type="text" id="ed-waPhone" value="${escH(menuData.waPhone||'')}" oninput="collectData();scheduleSave();updatePreview()">
          <p style="font-size:10px;color:var(--muted);margin-top:3px">Con código de país sin + (Ej: 52 para México)</p>
        </div>
        <div class="form-group-ed">
          <label>Texto del botón de envío</label>
          <input type="text" id="ed-waBtnText" value="${escH(menuData.waBtnText||'')}" oninput="collectData();scheduleSave();updatePreview()">
        </div>
        <div class="form-group-ed">
          <label>Prefijo del mensaje</label>
          <textarea id="ed-waPrefix" rows="2" oninput="collectData();scheduleSave();updatePreview()">${escH(menuData.waPrefix||'')}</textarea>
        </div>
        <div class="form-group-ed">
          <label>Mensaje después de enviar</label>
          <input type="text" id="ed-waSuccess" value="${escH(menuData.waSuccess||'')}" oninput="collectData();scheduleSave();updatePreview()">
        </div>
      </div>

      <div class="tab-content" id="tab-estilo">
        <div class="form-group-ed">
          <label>Color principal</label>
          <div class="color-row">
            <input type="color" id="ed-colorPrimary" value="${menuData.colorPrimary||'#b58b63'}" oninput="collectData();scheduleSave();updatePreview()">
            <span id="colorPrimaryVal" style="font-size:12px;color:var(--muted)">${menuData.colorPrimary||'#b58b63'}</span>
          </div>
        </div>
        <div class="form-group-ed">
          <label>Fondo de la app</label>
          <div class="color-row">
            <input type="color" id="ed-colorBg" value="${menuData.colorBg||'#f9f7f4'}" oninput="collectData();scheduleSave();updatePreview()">
            <span id="colorBgVal" style="font-size:12px;color:var(--muted)">${menuData.colorBg||'#f9f7f4'}</span>
          </div>
        </div>
        <div class="form-group-ed">
          <label>Fondo exterior</label>
          <div class="color-row">
            <input type="color" id="ed-colorOuter" value="${menuData.colorOuter||'#e9e4de'}" oninput="collectData();scheduleSave();updatePreview()">
            <span id="colorOuterVal" style="font-size:12px;color:var(--muted)">${menuData.colorOuter||'#e9e4de'}</span>
          </div>
        </div>
        <div class="form-group-ed">
          <label>Fuente</label>
          <select id="ed-fontFamily" onchange="collectData();scheduleSave();updatePreview()">
            ${['Poppins','Nunito','Raleway','Montserrat','Lato','Inter'].map(f=>`<option value="${f}" ${menuData.fontFamily===f?'selected':''}>${f}</option>`).join('')}
          </select>
        </div>
        ${extraStyle}
      </div>
    </div>

    <div class="download-bar">
      <div style="display:flex;align-items:center;justify-content:space-between">
        <span style="font-size:11px;color:var(--muted)"><span id="productCount">0</span> productos · <span id="sectionCount">0</span> secciones</span>
        <span class="badge badge-success">Autoguardado activo</span>
      </div>
      <button class="btn-full btn-primary" onclick="saveMenu()" style="margin-top:4px;padding:10px">
        💾 Guardar ahora
      </button>
    </div>
  </div>

  <div class="panel-right">
    <div class="preview-header">
      <span class="preview-label">Vista previa en tiempo real</span>
      <span class="badge badge-warn">📱 Mobile</span>
    </div>
    <div class="phone-frame">
      <div class="phone-screen">
        <iframe id="previewFrame" srcdoc=""></iframe>
      </div>
    </div>
  </div>
</div>`;
}

function goBackToDashboard() {
  if (confirm('¿Salir del editor? Los cambios sin guardar se perderán.')) {
    document.getElementById('screen-editor').innerHTML = '';
    showScreen('dashboard');
  }
}

function switchTab(tab, btn) {
  document.querySelectorAll('.ptab').forEach(t=>t.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(t=>t.classList.remove('active'));
  btn.classList.add('active');
  document.getElementById('tab-'+tab).classList.add('active');
}

function collectData() {
  const g = id => { const el = document.getElementById(id); return el ? el.value : ''; };
  menuData.name         = g('ed-name');
  menuData.emoji        = g('ed-emoji');
  menuData.welcome      = g('ed-welcome');
  menuData.currency     = g('ed-currency');
  menuData.waPhone      = g('ed-waPhone');
  menuData.waBtnText    = g('ed-waBtnText');
  menuData.waPrefix     = g('ed-waPrefix');
  menuData.waSuccess    = g('ed-waSuccess');
  menuData.colorPrimary = g('ed-colorPrimary');
  menuData.colorBg      = g('ed-colorBg');
  menuData.colorOuter   = g('ed-colorOuter');
  menuData.fontFamily   = g('ed-fontFamily');
  if (currentLayout === 1) menuData.borderRadius = g('ed-borderRadius');
  if (currentLayout === 2) { menuData.gridCols = g('ed-gridCols'); menuData.cardRadius = g('ed-cardRadius'); menuData.btnStyle = g('ed-btnStyle'); }
  const cpv = document.getElementById('colorPrimaryVal');
  const cbv = document.getElementById('colorBgVal');
  const cov = document.getElementById('colorOuterVal');
  if (cpv) cpv.textContent = menuData.colorPrimary;
  if (cbv) cbv.textContent = menuData.colorBg;
  if (cov) cov.textContent = menuData.colorOuter;
}

// ── IMAGE UPLOAD ──────────────────────────────────────────────
function fileToBase64(file) {
  return new Promise((res,rej)=>{const r=new FileReader();r.onload=e=>res(e.target.result);r.onerror=rej;r.readAsDataURL(file);});
}

function createImageUpload(si, pi) {
  const p = menuData.sections[si].products[pi];
  const wrap = document.createElement('div');
  wrap.className = 'form-group-ed';
  wrap.innerHTML = '<label>Imagen del producto</label>';
  const box = document.createElement('div');
  box.className = 'img-upload-box';

  const input = document.createElement('input');
  input.type = 'file'; input.accept = 'image/*';
  const ph = document.createElement('div');
  ph.className = 'img-upload-placeholder';
  ph.innerHTML = '<span class="icon">📷</span><span class="label">Clic o arrastra<br><span style="color:var(--brand);font-weight:600">Subir imagen</span></span>';
  box.appendChild(input); box.appendChild(ph);
  if (p.image) renderImgPreview(box, p.image, si, pi);

  const processFile = async (file) => {
    if (!file || !file.type.startsWith('image/')) return;
    if (file.size > 3*1024*1024) { alert('Máximo 3MB.'); return; }
    const ld = document.createElement('div');
    ld.className='img-upload-loading'; ld.textContent='Procesando...';
    box.appendChild(ld);
    try {
      const b64 = await fileToBase64(file);
      menuData.sections[si].products[pi].image = b64;
      ld.remove(); renderImgPreview(box, b64, si, pi);
      updateThumb(si, pi, b64); scheduleSave(); updatePreview();
    } catch(e) { ld.remove(); }
  };
  input.addEventListener('change', e => processFile(e.target.files[0]));
  box.addEventListener('dragover', e => { e.preventDefault(); box.style.borderColor='var(--brand)'; });
  box.addEventListener('dragleave', () => { box.style.borderColor=''; });
  box.addEventListener('drop', e => { e.preventDefault(); box.style.borderColor=''; processFile(e.dataTransfer.files[0]); });
  wrap.appendChild(box);
  return wrap;
}

function renderImgPreview(box, src, si, pi) {
  box.innerHTML = '';
  const img = document.createElement('img');
  img.className='img-upload-preview'; img.src=src;
  const clearBtn = document.createElement('button');
  clearBtn.className='img-upload-clear'; clearBtn.textContent='✕';
  clearBtn.onclick = e => { e.stopPropagation(); menuData.sections[si].products[pi].image=''; updateThumb(si,pi,''); scheduleSave(); updatePreview(); renderSectionsEditor(); };
  const input = document.createElement('input');
  input.type='file'; input.accept='image/*';
  input.style.cssText='position:absolute;inset:0;opacity:0;cursor:pointer;z-index:2;width:100%;height:100%';
  input.addEventListener('change', async e => {
    const file = e.target.files[0];
    if (!file || file.size > 3*1024*1024) { if(file) alert('Máximo 3MB.'); return; }
    const ld=document.createElement('div'); ld.className='img-upload-loading'; ld.textContent='Procesando...'; box.appendChild(ld);
    try { const b64=await fileToBase64(file); menuData.sections[si].products[pi].image=b64; ld.remove(); renderImgPreview(box,b64,si,pi); updateThumb(si,pi,b64); scheduleSave(); updatePreview(); } catch(e2){ld.remove();}
  });
  box.appendChild(img); box.appendChild(clearBtn); box.appendChild(input);
}

function updateThumb(si, pi, src) {
  const t=document.getElementById(`thumb-${si}-${pi}`);
  if(!t) return;
  t.innerHTML=src?`<img src="${src}" style="width:44px;height:44px;border-radius:10px;object-fit:cover">`:'🖼️';
}

// ── SECTIONS EDITOR ───────────────────────────────────────────
function renderSectionsEditor() {
  const container = document.getElementById('sections-editor');
  if (!container) return;
  container.innerHTML = '';
  let total = 0;
  menuData.sections.forEach((section, si) => {
    total += section.products.length;
    const card = document.createElement('div');
    card.className = 'section-card';
    const header = document.createElement('div');
    header.className = 'section-card-header';
    header.innerHTML = `<h3>📂 ${section.name}</h3><div style="display:flex;gap:3px">
      <button class="btn-icon" onclick="moveSectionUp(${si})">↑</button>
      <button class="btn-icon" onclick="moveSectionDown(${si})">↓</button>
      <button class="btn-icon danger" onclick="removeSection(${si})">🗑</button></div>`;
    card.appendChild(header);

    const nameRow = document.createElement('div');
    nameRow.className = 'product-row';
    if (currentLayout === 2) {
      nameRow.innerHTML = `
        <div class="form-group-ed"><label>Tab (botón)</label><input value="${escH(section.name)}" oninput="menuData.sections[${si}].name=this.value;scheduleSave();updatePreview()"></div>
        <div class="form-group-ed"><label>Título sección</label><input value="${escH(section.h2||section.name)}" oninput="menuData.sections[${si}].h2=this.value;scheduleSave();updatePreview()"></div>`;
    } else {
      nameRow.innerHTML = `<div class="form-group-ed" style="grid-column:1/-1"><label>Nombre de la sección</label><input value="${escH(section.name)}" oninput="menuData.sections[${si}].name=this.value;scheduleSave();updatePreview()"></div>`;
    }
    card.appendChild(nameRow);

    section.products.forEach((p, pi) => {
      const pc = document.createElement('div');
      pc.className = 'product-card';
      const pHeader = document.createElement('div');
      pHeader.className = 'product-card-header';
      const thumb = document.createElement('div');
      thumb.className='thumb-placeholder'; thumb.id=`thumb-${si}-${pi}`;
      thumb.innerHTML=p.image?`<img src="${p.image}" style="width:44px;height:44px;border-radius:10px;object-fit:cover">`:'🖼️';
      const pInfo = document.createElement('div');
      pInfo.style.cssText='flex:1;min-width:0';
      pInfo.innerHTML=`<div style="font-size:12px;font-weight:600">${escH(p.name)}</div><div style="font-size:11px;color:var(--muted)">${menuData.currency} ${p.price}</div>`;
      const delBtn=document.createElement('button'); delBtn.className='btn-icon danger'; delBtn.textContent='🗑';
      delBtn.onclick=()=>removeProduct(si,pi);
      pHeader.appendChild(thumb); pHeader.appendChild(pInfo); pHeader.appendChild(delBtn);
      pc.appendChild(pHeader);

      const row=document.createElement('div'); row.className='product-row';
      row.innerHTML=`<div class="form-group-ed"><label>Nombre</label><input value="${escH(p.name)}" oninput="menuData.sections[${si}].products[${pi}].name=this.value;scheduleSave();updatePreview()"></div>
        <div class="form-group-ed"><label>Precio</label><input type="number" value="${p.price}" oninput="menuData.sections[${si}].products[${pi}].price=this.value;scheduleSave();updatePreview()"></div>`;
      pc.appendChild(row);

      const descG=document.createElement('div'); descG.className='form-group-ed';
      descG.innerHTML=`<label>Descripción</label><input value="${escH(p.description)}" oninput="menuData.sections[${si}].products[${pi}].description=this.value;scheduleSave();updatePreview()">`;
      pc.appendChild(descG);
      pc.appendChild(createImageUpload(si,pi));
      card.appendChild(pc);
    });

    const addBtn=document.createElement('button'); addBtn.className='add-product-btn'; addBtn.textContent='+ Agregar producto';
    addBtn.onclick=()=>addProduct(si);
    card.appendChild(addBtn);
    container.appendChild(card);
  });
  const pc=document.getElementById('productCount');
  const sc=document.getElementById('sectionCount');
  if(pc) pc.textContent=total;
  if(sc) sc.textContent=menuData.sections.length;
}

function addSection() { menuData.sections.push({id:'sec_'+Date.now(),name:'Nueva Sección',h2:'Nueva Sección',products:[]}); renderSectionsEditor(); scheduleSave(); updatePreview(); }
function removeSection(si){ if(!confirm('¿Eliminar sección?')) return; menuData.sections.splice(si,1); renderSectionsEditor(); scheduleSave(); updatePreview(); }
function moveSectionUp(si){ if(si===0) return; [menuData.sections[si-1],menuData.sections[si]]=[menuData.sections[si],menuData.sections[si-1]]; renderSectionsEditor(); scheduleSave(); updatePreview(); }
function moveSectionDown(si){ if(si>=menuData.sections.length-1) return; [menuData.sections[si+1],menuData.sections[si]]=[menuData.sections[si],menuData.sections[si+1]]; renderSectionsEditor(); scheduleSave(); updatePreview(); }
function addProduct(si){ menuData.sections[si].products.push({id:'p'+Date.now(),name:'Nuevo Producto',price:'25',description:'Descripción',image:''}); renderSectionsEditor(); scheduleSave(); updatePreview(); }
function removeProduct(si,pi){ menuData.sections[si].products.splice(pi,1); renderSectionsEditor(); scheduleSave(); updatePreview(); }

// ── PREVIEW ───────────────────────────────────────────────────
function updatePreview() {
  collectData();
  clearTimeout(previewTimer);
  previewTimer = setTimeout(() => {
    const frame = document.getElementById('previewFrame');
    if (!frame) return;
    // Build minimal preview URL pointing to ver.php would require a save;
    // instead we generate inline HTML same as before (preview only, no download needed)
    frame.srcdoc = generatePreviewHTML();
  }, 300);
}

function darken(hex) {
  hex = hex || '#000000';
  const r=Math.max(0,parseInt(hex.slice(1,3),16)-20);
  const g=Math.max(0,parseInt(hex.slice(3,5),16)-20);
  const b=Math.max(0,parseInt(hex.slice(5,7),16)-20);
  return '#'+[r,g,b].map(x=>x.toString(16).padStart(2,'0')).join('');
}
function escHtml(s){ return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }

function generatePreviewHTML() {
  const d = menuData;
  const cp = d.colorPrimary||'#b58b63';
  const font = d.fontFamily||'Poppins';
  const tabsHTML = d.sections.map(s=>`<button class="tab" data-target="${escHtml(s.id)}">${escHtml(s.name)}</button>`).join('');
  const imgMap = {};
  d.sections.forEach(s=>s.products.forEach(p=>{ if(p.image) imgMap[p.name]=p.image; }));

  let sectHTML = '';
  let itemCSS = '';

  if (currentLayout === 1) {
    const radius = d.borderRadius||'22px';
    itemCSS = `.section{padding-top:20px;margin-bottom:40px}h2{font-size:18px;margin-bottom:14px}.item{display:flex;align-items:center;gap:14px;background:white;border-radius:${radius};padding:12px;box-shadow:0 8px 20px rgba(0,0,0,.06);margin-bottom:16px;cursor:pointer}.item-title{font-size:15px;font-weight:600;margin-bottom:4px}.price{font-size:14px;font-weight:600}.add-btn{width:42px;height:42px;min-width:42px;border-radius:50%;border:none;background:var(--color);color:white;font-size:20px;font-weight:600;cursor:pointer;flex-shrink:0}`;
    d.sections.forEach(s=>{
      const items = s.products.map(p=>{
        const imgHTML=p.image?`<img src="${p.image}" alt="${escHtml(p.name)}" style="width:75px;height:75px;object-fit:cover;border-radius:16px">`:`<div style="width:75px;height:75px;background:#e0d8d0;border-radius:16px;display:flex;align-items:center;justify-content:center;font-size:28px">🍽️</div>`;
        return `<div class="item"><div>${imgHTML}</div><div style="flex:1;min-width:0"><h3 class="item-title">${escHtml(p.name)}</h3><div class="price">$${p.price} ${d.currency}</div></div><button class="add-btn">+</button></div>`;
      }).join('');
      sectHTML += `<section id="${escHtml(s.id)}" class="section"><h2>${escHtml(s.name)}</h2>${items}</section>`;
    });
  } else {
    const cols=d.gridCols||'2'; const radius=d.cardRadius||'22px';
    const bs=d.btnStyle||'full';
    const abcss=bs==='outline'?`background:transparent;color:var(--color);border:2px solid var(--color);border-radius:12px`:bs==='round'?`background:var(--color);color:white;border:none;border-radius:50%;width:36px;height:36px`:`background:var(--color);color:white;border:none;border-radius:12px`;
    itemCSS=`.section{display:grid;grid-template-columns:repeat(${cols},1fr);gap:18px;padding-top:20px;margin-bottom:40px}.section h2{grid-column:1/-1;font-size:18px}.item{background:white;border-radius:${radius};padding:14px;box-shadow:0 8px 20px rgba(0,0,0,.06);display:flex;flex-direction:column;cursor:pointer}.item-image img{width:100%;height:120px;object-fit:cover;border-radius:16px}.price{font-size:14px;font-weight:600;margin-top:10px}.item-title{font-size:14px;font-weight:500;margin-top:4px}.add-btn{margin-top:10px;width:100%;height:34px;${abcss};font-size:16px;font-weight:600;cursor:pointer}`;
    d.sections.forEach(s=>{
      const items=s.products.map(p=>{
        const ih=p.image?`<div class="item-image"><img src="${p.image}" alt="${escHtml(p.name)}"></div>`:`<div class="item-image"><div style="width:100%;height:120px;background:#e0d8d0;border-radius:16px;display:flex;align-items:center;justify-content:center;font-size:40px">🍽️</div></div>`;
        return `<div class="item">${ih}<div class="price">$${p.price} ${d.currency}</div><h3 class="item-title">${escHtml(p.name)}</h3><button class="add-btn">+</button></div>`;
      }).join('');
      sectHTML+=`<section id="${escHtml(s.id)}" class="section"><h2>${escHtml(s.h2||s.name)}</h2>${items}</section>`;
    });
  }

  return `<!DOCTYPE html><html lang="es"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<link href="https://fonts.googleapis.com/css2?family=${encodeURIComponent(font)}:wght@400;500;600&display=swap" rel="stylesheet">
<style>*{margin:0;padding:0;box-sizing:border-box;font-family:'${font}',sans-serif}
:root{--color:${cp};--bg:${d.colorBg||'#f9f7f4'};--outer:${d.colorOuter||'#e9e4de'}}
body{background:var(--outer)}
.app{max-width:380px;background:var(--bg);border-radius:30px;padding:20px;min-height:100vh}
.top-bar{position:sticky;top:0;background:var(--bg);z-index:20;padding-bottom:12px}
.header h1{font-size:20px;font-weight:500;margin-bottom:14px}
.tabs{display:flex;gap:10px;overflow-x:auto;white-space:nowrap;padding:6px;background:white;border-radius:999px;scrollbar-width:none}
.tab{flex:0 0 auto;padding:12px 20px;border-radius:999px;border:none;background:transparent;font-weight:500;cursor:pointer}
.tab:first-child{background:var(--color);color:white}
${itemCSS}
${d.welcome?'.wm{background:white;border-radius:16px;padding:12px 16px;margin-bottom:16px;font-size:13px;color:#555;border-left:3px solid var(--color)}':''}
</style></head><body>
<div class="app">
  <div class="top-bar">
    <header class="header"><h1>${escHtml(d.emoji||'🍽️')} ${escHtml(d.name||'Mi Menú')}</h1></header>
    <div class="tabs">${tabsHTML}</div>
  </div>
  ${d.welcome?`<div class="wm">${escHtml(d.welcome)}</div>`:''}
  ${sectHTML}
</div>
</body></html>`;
}

// ── INIT ──────────────────────────────────────────────────────
checkAuth();
</script>
</body>
</html>
