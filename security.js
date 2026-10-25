/* ===== MediSec: các hàm bảo mật dùng chung =====
 * - Làm sạch dữ liệu nhập, chống XSS
 * - Kiểm tra email / SĐT / mật khẩu
 * - Khóa tạm khi đăng nhập sai nhiều lần (chống dò mật khẩu)
 * - Băm mật khẩu PBKDF2 + salt (chế độ LOCAL)
 * - Quản lý phiên có hạn dùng
 */
(function (global) {
  'use strict';

  var Sec = {};

  /* ---------- Lưu trữ an toàn (không lỗi khi bị chặn storage) ---------- */
  function store(kind) {
    try { return kind === 'local' ? global.localStorage : global.sessionStorage; }
    catch (e) { return null; }
  }
  Sec.read = function (kind, key) {
    var s = store(kind); if (!s) return null;
    try { return JSON.parse(s.getItem(key)); } catch (e) { return null; }
  };
  Sec.write = function (kind, key, val) {
    var s = store(kind); if (!s) return false;
    try { s.setItem(key, JSON.stringify(val)); return true; } catch (e) { return false; }
  };
  Sec.remove = function (kind, key) {
    var s = store(kind); if (s) { try { s.removeItem(key); } catch (e) {} }
  };

  /* ---------- Chống XSS / làm sạch ---------- */
  var ESC = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;', '`': '&#96;', '=': '&#61;', '/': '&#47;' };
  Sec.escapeHTML = function (s) {
    return String(s == null ? '' : s).replace(/[&<>"'`=\/]/g, function (c) { return ESC[c]; });
  };
  // Bỏ ký tự điều khiển, gộp khoảng trắng, giới hạn độ dài
  Sec.clean = function (s, max) {
    return String(s == null ? '' : s)
      .replace(/[\u0000-\u001F\u007F]/g, '')
      .replace(/\s+/g, ' ')
      .trim()
      .slice(0, max || 120);
  };
  // Chỉ cho phép chuyển hướng tới file .html cùng thư mục (chống open-redirect)
  Sec.safeNext = function (next, fallback) {
    return (typeof next === 'string' && /^[a-z0-9_-]+\.html$/i.test(next)) ? next : (fallback || 'index.html');
  };

  /* ---------- Kiểm tra dữ liệu ---------- */
  Sec.isEmail = function (e) {
    return typeof e === 'string' && e.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(e);
  };
  Sec.isPhoneVN = function (p) {
    if (!p) return true; // không bắt buộc
    return /^(0|\+84)\d{9}$/.test(String(p).replace(/[\s.\-]/g, ''));
  };
  Sec.isPastDate = function (d) {
    if (!d) return true;
    var t = Date.parse(d);
    return !isNaN(t) && t < Date.now() && t > Date.parse('1900-01-01');
  };
  // 0..4
  Sec.passwordScore = function (pw) {
    var s = 0;
    if (pw.length >= 8) s++;
    if (/[A-Z]/.test(pw) && /[a-z]/.test(pw)) s++;
    if (/\d/.test(pw)) s++;
    if (/[^A-Za-z0-9]/.test(pw)) s++;
    return s;
  };
  var COMMON = ['12345678', 'password', 'password1', 'qwerty123', '11111111', 'abc12345', 'iloveyou', '123456789', 'matkhau123'];
  // Trả về mảng lỗi (rỗng = hợp lệ)
  Sec.validatePassword = function (pw, email) {
    var errs = [];
    pw = String(pw || '');
    if (pw.length < 8) errs.push('Mật khẩu phải có ít nhất 8 ký tự.');
    if (pw.length > 128) errs.push('Mật khẩu tối đa 128 ký tự.');
    if (!/[a-z]/.test(pw) || !/[A-Z]/.test(pw)) errs.push('Mật khẩu cần có cả chữ hoa và chữ thường.');
    if (!/\d/.test(pw)) errs.push('Mật khẩu cần có ít nhất 1 chữ số.');
    if (!/[^A-Za-z0-9]/.test(pw)) errs.push('Mật khẩu cần có ít nhất 1 ký tự đặc biệt.');
    if (COMMON.indexOf(pw.toLowerCase()) > -1) errs.push('Mật khẩu quá phổ biến, hãy chọn mật khẩu khác.');
    if (email && pw.toLowerCase().indexOf(String(email).split('@')[0].toLowerCase()) > -1 && String(email).split('@')[0].length >= 4)
      errs.push('Mật khẩu không nên chứa tên email.');
    return errs;
  };

  /* ---------- Giới hạn đăng nhập sai ---------- */
  var MAX_TRIES = 5, LOCK_MS = 5 * 60 * 1000, WINDOW_MS = 15 * 60 * 1000;
  function rlKey(id) { return 'medi_rl_' + String(id).toLowerCase(); }
  Sec.limiter = {
    // → { locked: bool, waitMs: number }
    check: function (id) {
      var r = Sec.read('local', rlKey(id));
      if (r && r.lockedUntil && r.lockedUntil > Date.now()) return { locked: true, waitMs: r.lockedUntil - Date.now() };
      return { locked: false, waitMs: 0 };
    },
    fail: function (id) {
      var now = Date.now(), r = Sec.read('local', rlKey(id)) || { n: 0, first: now };
      if (now - r.first > WINDOW_MS) r = { n: 0, first: now };
      r.n++;
      if (r.n >= MAX_TRIES) { r.lockedUntil = now + LOCK_MS; r.n = 0; r.first = now; }
      Sec.write('local', rlKey(id), r);
      return { triesLeft: Math.max(0, MAX_TRIES - r.n), locked: !!(r.lockedUntil && r.lockedUntil > now) };
    },
    reset: function (id) { Sec.remove('local', rlKey(id)); }
  };

  /* ---------- Băm mật khẩu (chế độ LOCAL) ---------- */
  function b64(buf) {
    var a = new Uint8Array(buf), s = '';
    for (var i = 0; i < a.length; i++) s += String.fromCharCode(a[i]);
    return btoa(s);
  }
  function unb64(s) {
    var bin = atob(s), a = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) a[i] = bin.charCodeAt(i);
    return a;
  }
  var cr = global.crypto || (typeof require === 'function' ? require('crypto').webcrypto : null);
  Sec.hashPassword = async function (pw, saltB64) {
    var salt = saltB64 ? unb64(saltB64) : cr.getRandomValues(new Uint8Array(16));
    var key = await cr.subtle.importKey('raw', new TextEncoder().encode(pw), 'PBKDF2', false, ['deriveBits']);
    var bits = await cr.subtle.deriveBits({ name: 'PBKDF2', salt: salt, iterations: 150000, hash: 'SHA-256' }, key, 256);
    return { salt: b64(salt), hash: b64(bits) };
  };
  // So sánh thời gian không đổi
  Sec.safeEqual = function (a, b) {
    a = String(a); b = String(b);
    var d = a.length ^ b.length;
    for (var i = 0; i < Math.max(a.length, b.length); i++) d |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0);
    return d === 0;
  };
  Sec.randomId = function () {
    var a = cr.getRandomValues(new Uint8Array(12)), s = '';
    for (var i = 0; i < a.length; i++) s += ('0' + a[i].toString(16)).slice(-2);
    return s;
  };

  /* ---------- Phiên đăng nhập ---------- */
  var KEY = 'medi_session', IDLE_MS = 30 * 60 * 1000, REMEMBER_MS = 7 * 24 * 60 * 60 * 1000;
  Sec.session = {
    // user: {uid,email,name,role}
    set: function (user, remember) {
      var now = Date.now();
      var data = { uid: user.uid, email: user.email, name: user.name, role: user.role || 'user',
                   remember: !!remember, last: now, exp: now + (remember ? REMEMBER_MS : IDLE_MS) };
      Sec.remove('local', KEY); Sec.remove('session', KEY);
      Sec.write(remember ? 'local' : 'session', KEY, data);
      return data;
    },
    get: function () {
      var kind = Sec.read('local', KEY) ? 'local' : 'session';
      var s = Sec.read(kind, KEY);
      if (!s) return null;
      var now = Date.now();
      var idleExpired = !s.remember && (now - s.last > IDLE_MS);
      if (now > s.exp || idleExpired) { Sec.session.clear(); return null; }
      if (!s.remember) { s.last = now; s.exp = now + IDLE_MS; Sec.write(kind, KEY, s); } // gia hạn khi còn hoạt động
      return s;
    },
    clear: function () { Sec.remove('local', KEY); Sec.remove('session', KEY); }
  };

  global.MediSec = Sec;
  if (typeof module !== 'undefined' && module.exports) module.exports = Sec;
})(typeof window !== 'undefined' ? window : globalThis);
