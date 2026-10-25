/* ===== Cập nhật header theo trạng thái đăng nhập =====
 * Dùng textContent / createElement (không dùng innerHTML) để tên người dùng không thể chèn mã độc.
 */
(function () {
  'use strict';
  function el(tag, cls, text) {
    var n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text != null) n.textContent = text;
    return n;
  }
  function render() {
    var box = document.querySelector('.header-actions');
    if (!box || !window.MediAuth) return;
    var s = MediAuth.current();
    if (!s) return;
    box.textContent = '';
    var hello = el('span', 'nav-user', 'Xin chào, ' + s.name);
    hello.style.cssText = 'font-weight:700;align-self:center;max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap';
    box.appendChild(hello);
    if (s.role === 'admin') {
      var a = el('a', 'btn btn-outline', 'Admin'); a.href = 'admin.html'; box.appendChild(a);
    }
    var out = el('button', 'btn btn-primary', 'Logout');
    out.type = 'button';
    out.addEventListener('click', async function () { await MediAuth.logout(); location.href = 'index.html'; });
    box.appendChild(out);
    box.style.alignItems = 'center';
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', render); else render();
})();
