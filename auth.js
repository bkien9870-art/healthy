/* ===== MediAuth: đăng ký / đăng nhập / phân quyền =====
 * Hai chế độ (tự chọn theo js/firebase-config.js):
 *   - FIREBASE: Firebase Authentication + Firestore (collection "users")
 *   - LOCAL   : lưu trong localStorage, mật khẩu băm PBKDF2 + salt
 * Mọi hàm trả về { ok:true, ... } hoặc { ok:false, error:"thông báo tiếng Việt" }.
 */
(function (global) {
  'use strict';
  var Sec = global.MediSec, CFG = global.MEDI_CONFIG || {};
  var fb = CFG.firebase || {};
  var USE_FIREBASE = !!fb.apiKey && fb.apiKey.indexOf('YOUR_') !== 0;
  var USERS_KEY = 'medi_users';
  var GENERIC_LOGIN_ERR = 'Email hoặc mật khẩu không đúng.';

  /* ---------- Nạp Firebase (chỉ khi cần) ---------- */
  var fbReady = null;
  function loadScript(src) {
    return new Promise(function (res, rej) {
      var s = document.createElement('script');
      s.src = src; s.onload = res; s.onerror = function () { rej(new Error('load ' + src)); };
      document.head.appendChild(s);
    });
  }
  function initFirebase() {
    if (fbReady) return fbReady;
    var base = 'https://www.gstatic.com/firebasejs/10.12.2/';
    fbReady = loadScript(base + 'firebase-app-compat.js')
      .then(function () { return loadScript(base + 'firebase-auth-compat.js'); })
      .then(function () { return loadScript(base + 'firebase-firestore-compat.js'); })
      .then(function () {
        if (!global.firebase.apps.length) global.firebase.initializeApp(fb);
        return { auth: global.firebase.auth(), db: global.firebase.firestore() };
      });
    return fbReady;
  }

  /* ---------- Kiểm tra dữ liệu đăng ký ---------- */
  function validateRegister(d) {
    var errs = [];
    if (d.name.length < 2) errs.push('Vui lòng nhập họ và tên (ít nhất 2 ký tự).');
    if (!Sec.isEmail(d.email)) errs.push('Email không hợp lệ.');
    if (!Sec.isPhoneVN(d.phone)) errs.push('Số điện thoại không hợp lệ (VD: 0901234567).');
    if (!Sec.isPastDate(d.dob)) errs.push('Ngày sinh không hợp lệ.');
    if (['', 'male', 'female', 'other'].indexOf(d.gender) < 0) errs.push('Giới tính không hợp lệ.');
    errs = errs.concat(Sec.validatePassword(d.password, d.email));
    if (d.password !== d.confirm) errs.push('Mật khẩu xác nhận không khớp.');
    if (!d.terms) errs.push('Bạn cần đồng ý với điều khoản sử dụng.');
    return errs;
  }
  function normalize(raw) {
    return {
      name: Sec.clean(raw.name, 80).replace(/[<>]/g, ''),
      email: Sec.clean(raw.email, 254).toLowerCase(),
      phone: Sec.clean(raw.phone, 20).replace(/[\s.\-]/g, ''),
      dob: Sec.clean(raw.dob, 10),
      gender: Sec.clean(raw.gender, 10),
      password: String(raw.password || ''),
      confirm: String(raw.confirm || ''),
      newsletter: !!raw.newsletter,
      terms: !!raw.terms
    };
  }
  function fbError(e) {
    var c = (e && e.code) || '';
    if (c === 'auth/email-already-in-use') return 'Email này đã được đăng ký.';
    if (c === 'auth/weak-password') return 'Mật khẩu quá yếu.';
    if (c === 'auth/network-request-failed') return 'Lỗi mạng, vui lòng thử lại.';
    if (c === 'auth/too-many-requests') return 'Quá nhiều lần thử. Vui lòng đợi một lúc rồi thử lại.';
    if (c === 'auth/popup-closed-by-user') return 'Bạn đã đóng cửa sổ đăng nhập.';
    if (/invalid|user-not-found|wrong-password|credential/.test(c)) return GENERIC_LOGIN_ERR;
    return 'Có lỗi xảy ra, vui lòng thử lại.';
  }

  /* ---------- Kho người dùng LOCAL ---------- */
  function localUsers() { return Sec.read('local', USERS_KEY) || []; }
  function saveLocalUsers(u) { return Sec.write('local', USERS_KEY, u); }
  function publicUser(u) { return { uid: u.uid, email: u.email, name: u.name, role: u.role }; }

  var Auth = { mode: USE_FIREBASE ? 'firebase' : 'local' };

  /* ---------- Đăng ký ---------- */
  Auth.register = async function (raw) {
    var d = normalize(raw), errs = validateRegister(d);
    if (errs.length) return { ok: false, error: errs[0], errors: errs };
    try {
      if (USE_FIREBASE) {
        var f = await initFirebase();
        var cred = await f.auth.createUserWithEmailAndPassword(d.email, d.password);
        await cred.user.updateProfile({ displayName: d.name });
        // role luôn là "user"; firestore.rules chặn tự nâng quyền
        await f.db.collection('users').doc(cred.user.uid).set({
          name: d.name, email: d.email, phone: d.phone, dob: d.dob, gender: d.gender,
          role: 'user', newsletter: d.newsletter,
          createdAt: global.firebase.firestore.FieldValue.serverTimestamp()
        });
        await f.auth.signOut(); // bắt người dùng đăng nhập lại sau khi đăng ký
        return { ok: true };
      }
      var users = localUsers();
      if (users.some(function (u) { return u.email === d.email; })) return { ok: false, error: 'Email này đã được đăng ký.' };
      var h = await Sec.hashPassword(d.password);
      var isAdmin = (CFG.localAdminEmails || []).map(function (x) { return x.toLowerCase(); }).indexOf(d.email) > -1;
      users.push({ uid: Sec.randomId(), name: d.name, email: d.email, phone: d.phone, dob: d.dob, gender: d.gender,
                   newsletter: d.newsletter, role: isAdmin ? 'admin' : 'user', salt: h.salt, hash: h.hash, createdAt: Date.now() });
      if (!saveLocalUsers(users)) return { ok: false, error: 'Không thể lưu dữ liệu (trình duyệt chặn lưu trữ).' };
      return { ok: true };
    } catch (e) { return { ok: false, error: fbError(e) }; }
  };

  /* ---------- Đăng nhập ---------- */
  Auth.login = async function (email, password, remember) {
    email = Sec.clean(email, 254).toLowerCase();
    password = String(password || '');
    if (!Sec.isEmail(email) || !password) return { ok: false, error: 'Vui lòng nhập email và mật khẩu hợp lệ.' };

    var lim = Sec.limiter.check(email);
    if (lim.locked) return { ok: false, error: 'Đăng nhập sai quá nhiều lần. Thử lại sau ' + Math.ceil(lim.waitMs / 60000) + ' phút.' };

    try {
      var user = null;
      if (USE_FIREBASE) {
        var f = await initFirebase();
        var cred = await f.auth.signInWithEmailAndPassword(email, password);
        var snap = await f.db.collection('users').doc(cred.user.uid).get();
        var data = snap.exists ? snap.data() : {};
        user = { uid: cred.user.uid, email: cred.user.email, name: data.name || cred.user.displayName || email, role: data.role === 'admin' ? 'admin' : 'user' };
      } else {
        var found = localUsers().filter(function (u) { return u.email === email; })[0];
        // Luôn băm 1 lần dù email có tồn tại hay không → thời gian phản hồi như nhau
        var h = await Sec.hashPassword(password, found ? found.salt : null);
        if (found && Sec.safeEqual(h.hash, found.hash)) user = publicUser(found);
      }
      if (!user) throw { code: 'auth/invalid-credential' };
      Sec.limiter.reset(email);
      Sec.session.set(user, remember);
      return { ok: true, user: user };
    } catch (e) {
      var r = Sec.limiter.fail(email);
      var msg = fbError(e);
      if (r.locked) msg = 'Đăng nhập sai quá nhiều lần. Tài khoản bị khóa tạm 5 phút.';
      else if (msg === GENERIC_LOGIN_ERR && r.triesLeft <= 2) msg += ' Còn ' + r.triesLeft + ' lần thử.';
      return { ok: false, error: msg };
    }
  };

  /* Đăng nhập Google (chỉ chế độ Firebase) */
  Auth.loginGoogle = async function (remember) {
    if (!USE_FIREBASE) return { ok: false, error: 'Đăng nhập Google cần bật Firebase (xem js/firebase-config.js).' };
    try {
      var f = await initFirebase();
      var provider = new global.firebase.auth.GoogleAuthProvider();
      var cred = await f.auth.signInWithPopup(provider);
      var ref = f.db.collection('users').doc(cred.user.uid);
      var snap = await ref.get();
      if (!snap.exists) {
        await ref.set({ name: Sec.clean(cred.user.displayName || cred.user.email, 80), email: cred.user.email, phone: '', dob: '', gender: '',
                        role: 'user', newsletter: false, createdAt: global.firebase.firestore.FieldValue.serverTimestamp() });
        snap = await ref.get();
      }
      var d = snap.data();
      var user = { uid: cred.user.uid, email: cred.user.email, name: d.name, role: d.role === 'admin' ? 'admin' : 'user' };
      Sec.session.set(user, remember);
      return { ok: true, user: user };
    } catch (e) { return { ok: false, error: fbError(e) }; }
  };

  /* ---------- Đăng xuất / trạng thái ---------- */
  Auth.logout = async function () {
    Sec.session.clear();
    if (USE_FIREBASE) { try { var f = await initFirebase(); await f.auth.signOut(); } catch (e) {} }
  };
  Auth.current = function () { return Sec.session.get(); };
  Auth.isAdmin = function () { var s = Sec.session.get(); return !!s && s.role === 'admin'; };

  /* ---------- Bảo vệ trang ---------- */
  // opts: { role: 'admin' }  — chưa đăng nhập → về login.html?next=<trang này>
  Auth.guard = function (opts) {
    opts = opts || {};
    var page = (location.pathname.split('/').pop() || 'index.html');
    var s = Sec.session.get();
    var denied = !s || (opts.role && s.role !== opts.role);
    if (denied) {
      document.documentElement.style.display = 'none'; // không cho nhìn thấy nội dung trong lúc chuyển hướng
      location.replace('login.html?next=' + encodeURIComponent(page) + (s ? '&denied=1' : ''));
      return false;
    }
    return true;
  };
  Auth.nextUrl = function () {
    var p = new URLSearchParams(location.search);
    return Sec.safeNext(p.get('next'), 'index.html');
  };

  global.MediAuth = Auth;
  if (typeof module !== 'undefined' && module.exports) module.exports = Auth;
})(typeof window !== 'undefined' ? window : globalThis);
