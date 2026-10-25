/* ===== Cấu hình MediCare =====
 * CÁCH BẬT FIREBASE (khuyến nghị khi nộp bài):
 *  1. Vào https://console.firebase.google.com → Add project
 *  2. Build → Authentication → Sign-in method → bật "Email/Password" (và "Google" nếu muốn)
 *  3. Build → Firestore Database → Create database
 *  4. Project settings → Your apps → Web (</>) → copy firebaseConfig dán vào bên dưới
 *  5. Firestore → Rules → dán nội dung file firestore.rules → Publish
 *  6. Muốn có tài khoản admin: đăng ký 1 tài khoản bình thường, rồi vào Firestore
 *     collection "users" → document của tài khoản đó → sửa field role = "admin"
 *
 * Nếu chưa điền apiKey, website tự chạy ở chế độ LOCAL (lưu trong trình duyệt)
 * để vẫn demo được đăng ký / đăng nhập.
 */
window.MEDI_CONFIG = {
  firebase: {
    apiKey: "YOUR_API_KEY",
    authDomain: "YOUR_PROJECT.firebaseapp.com",
    projectId: "YOUR_PROJECT",
    storageBucket: "YOUR_PROJECT.appspot.com",
    messagingSenderId: "000000000000",
    appId: "YOUR_APP_ID"
  },
  // Chỉ dùng ở chế độ LOCAL: email nằm trong danh sách này sẽ có quyền admin khi đăng ký.
  // (Ở chế độ Firebase, quyền admin chỉ gán thủ công trong Firestore.)
  localAdminEmails: ["admin@medicare.test"]
};
