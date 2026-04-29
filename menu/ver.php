<?php
// ver.php — Visualiza un menú guardado públicamente
// URL: https://tudominio.com/menu-system/ver.php?slug=nombre-del-menu
require_once __DIR__ . '/config.php';

$slug = trim($_GET['slug'] ?? '');
if (!$slug) { http_response_code(404); die('Menú no encontrado'); }

$db = getDB();
$st = $db->prepare('SELECT layout, data FROM menus WHERE slug = ?');
$st->execute([$slug]);
$row = $st->fetch();
if (!$row) { http_response_code(404); die('Menú no encontrado'); }

$layout = (int)$row['layout'];
$d = json_decode($row['data'], true);

function escH($s) { return htmlspecialchars((string)($s ?? ''), ENT_QUOTES, 'UTF-8'); }
function darken($hex) {
    $r = max(0, hexdec(substr($hex,1,2))-20);
    $g = max(0, hexdec(substr($hex,3,2))-20);
    $b = max(0, hexdec(substr($hex,5,2))-20);
    return sprintf('#%02x%02x%02x', $r, $g, $b);
}

$cp    = $d['colorPrimary'] ?? '#b58b63';
$cbg   = $d['colorBg']      ?? '#f9f7f4';
$couter= $d['colorOuter']   ?? '#e9e4de';
$font  = $d['fontFamily']   ?? 'Poppins';
$waPhone  = $d['waPhone']   ?? '';
$waBtnText= $d['waBtnText'] ?? 'Enviar pedido por WhatsApp';
$waPrefix = addslashes($d['waPrefix'] ?? 'Hola, quiero hacer el siguiente pedido:');
$waSuccess= addslashes($d['waSuccess'] ?? '✅ Pedido enviado');
$currency = $d['currency']  ?? 'MXN';

// Tabs HTML
$tabsHTML = '';
foreach ($d['sections'] as $s) {
    $tabsHTML .= '<button class="tab" data-target="' . escH($s['id']) . '">' . escH($s['name']) . '</button>' . "\n";
}

// Image map JS (evita duplicar base64 en data attrs)
$imgMap = [];
foreach ($d['sections'] as $s) {
    foreach ($s['products'] as $p) {
        if (!empty($p['image'])) $imgMap[$p['name']] = $p['image'];
    }
}
$imgMapJS = json_encode($imgMap);

// Sections HTML — difiere según layout
if ($layout === 1) {
    // Layout 1: Lista horizontal
    $radius = $d['borderRadius'] ?? '22px';
    $sectHTML = '';
    foreach ($d['sections'] as $s) {
        $items = '';
        foreach ($s['products'] as $p) {
            $imgHTML = !empty($p['image'])
                ? '<img src="' . escH($p['image']) . '" alt="' . escH($p['name']) . '" style="width:75px;height:75px;object-fit:cover;border-radius:16px">'
                : '<div style="width:75px;height:75px;background:#e0d8d0;border-radius:16px;display:flex;align-items:center;justify-content:center;font-size:28px">🍽️</div>';
            $items .= '
      <div class="item" data-name="' . escH($p['name']) . '" data-description="' . escH($p['description']) . '" data-price="' . escH($p['price']) . '">
        <div class="item-image">' . $imgHTML . '</div>
        <div style="flex:1;min-width:0">
          <h3 class="item-title">' . escH($p['name']) . '</h3>
          <div class="price">$' . escH($p['price']) . ' ' . escH($currency) . '</div>
        </div>
        <button class="add-btn">+</button>
      </div>';
        }
        $sectHTML .= '<section id="' . escH($s['id']) . '" class="section"><h2>' . escH($s['name']) . '</h2>' . $items . '</section>';
    }
    $itemCSS = '.item{display:flex;align-items:center;gap:14px;background:white;border-radius:' . $radius . ';padding:12px;box-shadow:0 8px 20px rgba(0,0,0,.06);margin-bottom:16px;cursor:pointer}.item-title{font-size:15px;font-weight:600;margin-bottom:4px}.price{font-size:14px;font-weight:600}.add-btn{width:42px;height:42px;min-width:42px;border-radius:50%;border:none;background:var(--color);color:white;font-size:20px;font-weight:600;cursor:pointer;display:flex;align-items:center;justify-content:center;flex-shrink:0}.section{padding-top:20px;margin-bottom:40px}h2{font-size:18px;margin-bottom:14px}';
} else {
    // Layout 2: Grid 2 columnas
    $cols   = $d['gridCols']   ?? '2';
    $radius = $d['cardRadius'] ?? '22px';
    $btnStyle = $d['btnStyle'] ?? 'full';
    if ($btnStyle === 'outline')
        $addBtnCSS = 'background:transparent;color:var(--color);border:2px solid var(--color);border-radius:12px;';
    elseif ($btnStyle === 'round')
        $addBtnCSS = 'background:var(--color);color:white;border:none;border-radius:50%;width:36px;height:36px;';
    else
        $addBtnCSS = 'background:var(--color);color:white;border:none;border-radius:12px;';

    $sectHTML = '';
    foreach ($d['sections'] as $s) {
        $items = '';
        foreach ($s['products'] as $p) {
            $imgHTML = !empty($p['image'])
                ? '<div class="item-image"><img src="' . escH($p['image']) . '" alt="' . escH($p['name']) . '"></div>'
                : '<div class="item-image"><div style="width:100%;height:120px;background:#e0d8d0;border-radius:16px;display:flex;align-items:center;justify-content:center;font-size:40px">🍽️</div></div>';
            $items .= '
      <div class="item" data-name="' . escH($p['name']) . '" data-description="' . escH($p['description']) . '" data-price="' . escH($p['price']) . '">
        ' . $imgHTML . '
        <div class="price">$' . escH($p['price']) . ' ' . escH($currency) . '</div>
        <h3 class="item-title">' . escH($p['name']) . '</h3>
        <button class="add-btn">+</button>
      </div>';
        }
        $sectHTML .= '<section id="' . escH($s['id']) . '" class="section"><h2>' . escH($s['h2'] ?? $s['name']) . '</h2>' . $items . '</section>';
    }
    $itemCSS = '.section{display:grid;grid-template-columns:repeat(' . $cols . ',1fr);gap:18px;padding-top:20px;margin-bottom:40px}.section h2{grid-column:1/-1;font-size:18px;margin-bottom:0}.item{background:white;border-radius:' . $radius . ';padding:14px;box-shadow:0 8px 20px rgba(0,0,0,.06);display:flex;flex-direction:column;position:relative;cursor:pointer}.item-image img{width:100%;height:120px;object-fit:cover;border-radius:16px}.price{font-size:14px;font-weight:600;margin-top:10px}.item-title{font-size:14px;font-weight:500;margin-top:4px}.add-btn{margin-top:10px;width:100%;height:34px;' . $addBtnCSS . 'font-size:16px;font-weight:600;cursor:pointer}';
}

$welcomeHTML = !empty($d['welcome'])
    ? '<div class="welcome-msg">' . escH($d['welcome']) . '</div>'
    : '';
$welcomeCSS = !empty($d['welcome'])
    ? '.welcome-msg{background:white;border-radius:16px;padding:12px 16px;margin-bottom:16px;font-size:13px;color:#555;border-left:3px solid var(--color)}'
    : '';
?>
<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover">
  <title><?= escH($d['name']) ?></title>
  <link href="https://fonts.googleapis.com/css2?family=<?= urlencode($font) ?>:wght@400;500;600&display=swap" rel="stylesheet">
  <style>
    *{margin:0;padding:0;box-sizing:border-box;font-family:'<?= escH($font) ?>',sans-serif}
    :root{--color:<?= $cp ?>;--color-dark:<?= darken($cp) ?>;--bg:<?= $cbg ?>;--outer:<?= $couter ?>}
    body{background:var(--outer);margin:0}
    .app{width:100%;max-width:420px;margin:0 auto;background:var(--bg);border-radius:30px;padding:20px;min-height:100vh;box-shadow:0 20px 60px rgba(0,0,0,.12)}
    .top-bar{position:sticky;top:0;background:var(--bg);z-index:100;padding-bottom:12px}
    .header h1{font-size:20px;color:#000;font-weight:500;margin-bottom:14px}
    .tabs{display:flex;gap:10px;overflow-x:auto;white-space:nowrap;padding:6px;background:white;border-radius:999px;scrollbar-width:none}
    .tabs::-webkit-scrollbar{display:none}
    .tab{flex:0 0 auto;padding:12px 20px;border-radius:999px;border:none;background:transparent;font-weight:500;cursor:pointer;color:#000}
    .tab.active{background:var(--color);color:white}
    <?= $itemCSS ?>
    <?= $welcomeCSS ?>
    .overlay{position:fixed;inset:0;background:rgba(0,0,0,.5);opacity:0;pointer-events:none;transition:opacity .3s;z-index:90}
    .overlay.active{opacity:1;pointer-events:all}
    .product-modal{position:fixed;left:0;right:0;bottom:-100%;max-height:90vh;background:white;border-top-left-radius:24px;border-top-right-radius:24px;transition:.4s ease;z-index:100;display:flex}
    .product-modal.active{bottom:0}
    .modal-content{width:100%;padding:20px;display:flex;flex-direction:column;overflow-y:auto;max-height:90vh}
    .modal-content img{width:100%;height:220px;object-fit:cover;border-radius:16px;margin-bottom:15px}
    .modal-no-img{width:100%;height:160px;background:#f1ece6;border-radius:16px;display:flex;align-items:center;justify-content:center;font-size:56px;margin-bottom:15px}
    .modal-info h2{margin-bottom:6px}
    textarea{margin-top:15px;padding:12px;border-radius:12px;border:1px solid #ddd;resize:none;height:80px;font-family:inherit;width:100%}
    .modal-footer{margin-top:16px;display:flex;justify-content:space-between;align-items:center}
    .quantity{display:flex;align-items:center;gap:10px}
    .quantity button{width:32px;height:32px;border-radius:50%;border:none;background:#eee;font-size:18px;cursor:pointer}
    .add-cart-btn{background:var(--color);color:white;border:none;padding:12px 18px;border-radius:999px;font-weight:600;cursor:pointer}
    .close-modal{position:absolute;top:16px;right:16px;width:34px;height:34px;border-radius:50%;border:none;background:rgba(255,255,255,.9);font-size:16px;font-weight:bold;cursor:pointer;box-shadow:0 2px 8px rgba(0,0,0,.1)}
    .cart-bar{position:fixed;bottom:0;left:0;right:0;height:64px;background:white;display:flex;align-items:center;justify-content:space-between;padding:0 16px;box-shadow:0 -4px 12px rgba(0,0,0,.08);transform:translateY(100%);transition:.4s ease;z-index:200}
    .cart-bar.active{transform:translateY(0)}
    .cart-images{display:flex;gap:6px}
    .cart-images img{width:36px;height:36px;border-radius:8px;object-fit:cover}
    .cart-info{display:flex;flex-direction:column;font-size:13px}
    .go-cart{background:var(--color);color:white;border:none;padding:8px 14px;border-radius:999px;font-weight:600;cursor:pointer}
    .cart-sheet{position:fixed;left:0;right:0;bottom:0;height:100%;background:white;border-radius:24px 24px 0 0;transform:translateY(100%);transition:transform .4s ease;z-index:2000;display:flex;flex-direction:column}
    .cart-sheet.active{transform:translateY(0)}
    .cart-sheet-header{display:flex;justify-content:space-between;padding:20px;font-weight:bold;border-bottom:1px solid #eee}
    .cart-sheet-content{flex:1;overflow-y:auto;padding:15px}
    .cart-whatsapp{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:16px;border-top:1px solid #eee}
    #sendWhatsApp{padding:14px 18px;border:none;border-radius:14px;background:#25D366;color:white;font-weight:600;font-size:15px;cursor:pointer}
    .cart-total{font-size:16px;font-weight:600}
    .cart-item{position:relative;background:#fff;border-radius:12px;margin-bottom:12px;overflow:hidden}
    .cart-item-inner{display:flex;align-items:center;padding:12px;background:white;position:relative;z-index:2;transition:transform .3s}
    .cart-item.swiped .cart-item-inner{transform:translateX(-80px)}
    .delete-zone{position:absolute;right:0;top:0;height:100%;width:80px;background:#e53935;display:flex;justify-content:center;align-items:center;color:white;font-weight:bold;cursor:pointer}
    .cart-item img{width:55px;height:55px;border-radius:10px;object-fit:cover;margin-right:12px}
    .cart-thumb-ph{width:55px;height:55px;border-radius:10px;background:#f1ece6;display:flex;align-items:center;justify-content:center;font-size:22px;margin-right:12px;flex-shrink:0}
    .cart-controls{margin-left:auto;display:flex;align-items:center;gap:10px}
    .cart-controls button{border:none;background:#f2f2f2;padding:6px 10px;border-radius:8px;font-size:16px;cursor:pointer}
    #closeCart{width:36px;height:36px;border-radius:50%;border:none;background:#f1ece6;font-size:18px;cursor:pointer}
    .confirm-modal{position:fixed;inset:0;background:rgba(0,0,0,.4);display:none;justify-content:center;align-items:flex-end;z-index:3000}
    .confirm-modal.active{display:flex}
    .confirm-content{background:white;width:100%;border-radius:24px 24px 0 0;padding:20px;max-height:80%;overflow-y:auto}
    .confirm-content h3{margin-bottom:15px}
    .confirm-item{display:flex;align-items:center;margin-bottom:12px}
    .confirm-item img{width:45px;height:45px;border-radius:8px;object-fit:cover;margin-right:10px}
    .confirm-item-ph{width:45px;height:45px;border-radius:8px;background:#f1ece6;display:flex;align-items:center;justify-content:center;font-size:18px;margin-right:10px;flex-shrink:0}
    .confirm-total{font-weight:bold;margin:15px 0;font-size:16px}
    .confirm-buttons{display:flex;gap:10px}
    #cancelConfirm{flex:1;padding:12px;border:none;border-radius:12px;background:#eee;cursor:pointer}
    #confirmSend{flex:1;padding:12px;border:none;border-radius:12px;background:#25D366;color:white;font-weight:600;cursor:pointer}
    .success-toast{position:fixed;bottom:80px;left:50%;transform:translateX(-50%) translateY(20px);background:#1a1a1a;color:white;padding:12px 20px;border-radius:999px;font-size:14px;opacity:0;transition:.3s;z-index:9999;white-space:nowrap}
    .success-toast.show{opacity:1;transform:translateX(-50%) translateY(0)}
  </style>
</head>
<body>
<div class="app">
  <div class="top-bar">
    <header class="header"><h1><?= escH($d['emoji'] ?? '🍽️') ?> <?= escH($d['name']) ?></h1></header>
    <div class="tabs"><?= $tabsHTML ?></div>
  </div>
  <?= $welcomeHTML ?>
  <?= $sectHTML ?>
</div>
<div class="overlay"></div>
<div class="product-modal">
  <div class="modal-content">
    <button class="close-modal">✕</button>
    <div id="modalImgWrap"></div>
    <div class="modal-info"><h2 id="modalName"></h2><p id="modalDescription"></p></div>
    <textarea id="modalNotes" placeholder="Instrucciones especiales..."></textarea>
    <div class="modal-footer">
      <div class="quantity"><button id="minus">-</button><span id="quantityValue">1</span><button id="plus">+</button></div>
      <button class="add-cart-btn">Agregar al carrito</button>
    </div>
  </div>
</div>
<div class="cart-bar">
  <div class="cart-images"></div>
  <div class="cart-info"><span id="cartCount">0 productos</span><span id="cartTotal">$0</span></div>
  <button id="goToCart" class="go-cart">Ver carrito</button>
</div>
<div class="cart-sheet" id="cartSheet">
  <div class="cart-sheet-header"><span>Tu carrito</span><button id="closeCart">✕</button></div>
  <div class="cart-sheet-content" id="cartSheetContent"></div>
  <div class="cart-whatsapp">
    <div class="cart-total">Total: <span id="sheetTotal">$0</span></div>
    <button id="sendWhatsApp"><?= escH($waBtnText) ?></button>
  </div>
</div>
<div class="confirm-modal" id="confirmModal">
  <div class="confirm-content">
    <h3>Confirmar pedido</h3>
    <div id="confirmItems"></div>
    <div class="confirm-total">Total: <span id="confirmTotal">$0</span></div>
    <div class="confirm-buttons">
      <button id="cancelConfirm">Cancelar</button>
      <button id="confirmSend">Confirmar y enviar</button>
    </div>
  </div>
</div>
<script>
var cart=[];
var WA_PHONE="<?= addslashes($d['waPhone'] ?? '') ?>";
var WA_PREFIX="<?= $waPrefix ?>";
var SUCCESS_MSG="<?= $waSuccess ?>";
var CURRENCY="<?= escH($currency) ?>";
var IMG_MAP=<?= $imgMapJS ?>;
document.addEventListener("DOMContentLoaded",function(){
  var tabs=document.querySelectorAll(".tab");
  var sections=document.querySelectorAll(".section");
  var topBar=document.querySelector(".top-bar");
  var modal=document.querySelector(".product-modal");
  var overlay=document.querySelector(".overlay");
  var modalImgWrap=document.getElementById("modalImgWrap");
  var modalName=document.getElementById("modalName");
  var modalDescription=document.getElementById("modalDescription");
  var quantityValue=document.getElementById("quantityValue");
  var cartBar=document.querySelector(".cart-bar");
  var cartImagesEl=document.querySelector(".cart-images");
  var cartCount=document.getElementById("cartCount");
  var cartTotal=document.getElementById("cartTotal");
  var sheetTotal=document.getElementById("sheetTotal");
  var cartSheet=document.getElementById("cartSheet");
  var cartSheetContent=document.getElementById("cartSheetContent");
  var confirmModal=document.getElementById("confirmModal");
  var confirmItemsEl=document.getElementById("confirmItems");
  var confirmTotal=document.getElementById("confirmTotal");
  var quantity=1;
  var currentActive="";
  var currentItem={};
  tabs.forEach(function(tab){
    tab.addEventListener("click",function(){
      var target=document.getElementById(tab.dataset.target);
      var offset=topBar.offsetHeight+20;
      window.scrollTo({top:target.getBoundingClientRect().top+window.pageYOffset-offset,behavior:"smooth"});
    });
  });
  window.addEventListener("scroll",function(){
    sections.forEach(function(section){
      var st=section.offsetTop-topBar.offsetHeight-60;
      if(window.scrollY>=st&&window.scrollY<st+section.offsetHeight) currentActive=section.id;
    });
    tabs.forEach(function(tab){
      tab.classList.remove("active");
      if(tab.dataset.target===currentActive){tab.classList.add("active");var tc=document.querySelector(".tabs");tc.scrollTo({left:tab.offsetLeft-(tc.offsetWidth/2)+(tab.offsetWidth/2),behavior:"smooth"});}
    });
  });
  document.querySelectorAll(".add-btn").forEach(function(btn){
    btn.addEventListener("click",function(e){
      var item=e.target.closest(".item");
      var name=item.dataset.name;
      var imgSrc=IMG_MAP[name]||"";
      currentItem={name:name,description:item.dataset.description,price:item.dataset.price,imgsrc:imgSrc};
      modalImgWrap.innerHTML=imgSrc?'<img src="'+imgSrc+'" alt="">':'<div class="modal-no-img">🍽️</div>';
      modalName.textContent=name;
      modalDescription.textContent=item.dataset.description;
      quantity=1;quantityValue.textContent=1;
      modal.classList.add("active");overlay.classList.add("active");cartBar.classList.remove("active");
    });
  });
  document.getElementById("plus").addEventListener("click",function(){quantity++;quantityValue.textContent=quantity;});
  document.getElementById("minus").addEventListener("click",function(){if(quantity>1){quantity--;quantityValue.textContent=quantity;}});
  overlay.addEventListener("click",closeModal);
  document.querySelector(".close-modal").addEventListener("click",closeModal);
  function closeModal(){modal.classList.remove("active");overlay.classList.remove("active");if(cart.length>0)cartBar.classList.add("active");}
  document.querySelector(".add-cart-btn").addEventListener("click",function(){
    var price=parseFloat(currentItem.price);
    var note=document.getElementById("modalNotes").value.trim();
    var ex=cart.find(function(i){return i.name===currentItem.name&&i.price===price&&i.note===note;});
    if(ex){ex.quantity+=quantity;}else{cart.push({name:currentItem.name,imgsrc:currentItem.imgsrc,price:price,quantity:quantity,note:note});}
    document.getElementById("modalNotes").value="";
    if(navigator.vibrate)navigator.vibrate(50);
    updateCartBar();closeModal();
  });
  function updateCartBar(){
    if(cart.length===0){cartBar.classList.remove("active");return;}
    cartBar.classList.add("active");cartImagesEl.innerHTML="";
    var ti=0,tp=0;
    cart.forEach(function(i){ti+=i.quantity;tp+=i.price*i.quantity;});
    cart.slice(0,2).forEach(function(i){if(i.imgsrc){var img=document.createElement("img");img.src=i.imgsrc;cartImagesEl.appendChild(img);}});
    cartCount.textContent=ti+" producto"+(ti>1?"s":"");
    var ts="$"+tp+" "+CURRENCY;cartTotal.textContent=ts;sheetTotal.textContent=ts;
  }
  document.getElementById("goToCart").addEventListener("click",function(){renderCart();cartSheet.classList.add("active");});
  document.getElementById("closeCart").addEventListener("click",function(){cartSheet.classList.remove("active");});
  function renderCart(){
    cartSheetContent.innerHTML="";
    cart.forEach(function(product,index){
      var item=document.createElement("div");item.classList.add("cart-item");
      var th=product.imgsrc?'<img src="'+product.imgsrc+'" />':'<div class="cart-thumb-ph">🍽️</div>';
      item.innerHTML='<div class="delete-zone">Eliminar</div><div class="cart-item-inner">'+th+'<div><div>'+product.name+'</div><small>$'+product.price+' '+CURRENCY+'</small></div><div class="cart-controls">'+(product.quantity>1?'<button class="minus">-</button>':'<button class="trash">🗑</button>')+'<span>'+product.quantity+'</span><button class="plus">+</button></div></div>';
      item.querySelector(".plus").addEventListener("click",function(){cart[index].quantity++;renderCart();updateCartBar();});
      var m=item.querySelector(".minus");if(m)m.addEventListener("click",function(){cart[index].quantity--;renderCart();updateCartBar();});
      var t=item.querySelector(".trash");if(t)t.addEventListener("click",function(){cart.splice(index,1);renderCart();updateCartBar();});
      cartSheetContent.appendChild(item);
    });
  }
  document.getElementById("sendWhatsApp").addEventListener("click",function(){
    if(cart.length===0)return;
    confirmItemsEl.innerHTML="";var total=0;
    cart.forEach(function(item){
      var sub=item.price*item.quantity;total+=sub;
      var div=document.createElement("div");div.classList.add("confirm-item");
      var th=item.imgsrc?'<img src="'+item.imgsrc+'" />':'<div class="confirm-item-ph">🍽️</div>';
      div.innerHTML=th+'<div><div>'+item.name+'</div><small>'+item.quantity+' x $'+item.price+'</small></div><div style="margin-left:auto;font-weight:bold">$'+sub+'</div>';
      confirmItemsEl.appendChild(div);
    });
    confirmTotal.textContent="$"+total+" "+CURRENCY;
    confirmModal.classList.add("active");
  });
  document.getElementById("cancelConfirm").addEventListener("click",function(){confirmModal.classList.remove("active");});
  document.getElementById("confirmSend").addEventListener("click",function(){
    var msg=WA_PREFIX+"\n\n";var total=0;
    cart.forEach(function(item){
      var sub=item.price*item.quantity;total+=sub;
      msg+="• "+item.name+" x"+item.quantity+" - $"+sub+" "+CURRENCY;
      if(item.note&&item.note.trim()!=="")msg+="\n  📝 Nota: "+item.note;
      msg+="\n";
    });
    msg+="\nTotal: $"+total+" "+CURRENCY;
    window.open("https://wa.me/"+WA_PHONE+"?text="+encodeURIComponent(msg),"_blank");
    cart=[];updateCartBar();renderCart();
    confirmModal.classList.remove("active");cartSheet.classList.remove("active");
    var toast=document.createElement("div");toast.classList.add("success-toast");toast.textContent=SUCCESS_MSG;
    document.body.appendChild(toast);
    setTimeout(function(){toast.classList.add("show");},50);
    setTimeout(function(){toast.classList.remove("show");setTimeout(function(){toast.remove();},300);},2500);
  });
});
</script>
</body>
</html>
