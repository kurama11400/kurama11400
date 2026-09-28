<?php
session_start();
require_once "koneksi.php";

function e($value) {
    return htmlspecialchars((string)$value, ENT_QUOTES, 'UTF-8');
}

function redirect_home() {
    header("Location: index.php");
    exit;
}

/* Buat akun bawaan jika belum ada */
$defaultUsers = [
    ["admin", "admin123", "admin"],
    ["habil", "habil123", "user"]
];

foreach ($defaultUsers as $du) {
    $check = $koneksi->prepare("SELECT id FROM users WHERE username = ?");
    $check->bind_param("s", $du[0]);
    $check->execute();
    $result = $check->get_result();

    if ($result->num_rows === 0) {
        $hash = password_hash($du[1], PASSWORD_DEFAULT);
        $ins = $koneksi->prepare("INSERT INTO users (username,password,role) VALUES (?,?,?)");
        $ins->bind_param("sss", $du[0], $hash, $du[2]);
        $ins->execute();
    }
}

/* Logout */
if (isset($_GET["logout"])) {
    session_unset();
    session_destroy();
    header("Location: index.php");
    exit;
}

/* Login */
if ($_SERVER["REQUEST_METHOD"] === "POST" && ($_POST["action"] ?? "") === "login") {
    if (!isset($_SESSION["login_attempts"])) $_SESSION["login_attempts"] = 0;
    if (!isset($_SESSION["lock_until"])) $_SESSION["lock_until"] = 0;

    if (time() < $_SESSION["lock_until"]) {
        $sisa = $_SESSION["lock_until"] - time();
        $_SESSION["login_error"] = "Login dikunci. Coba lagi dalam {$sisa} detik.";
        redirect_home();
    }

    $username = trim($_POST["username"] ?? "");
    $password = $_POST["password"] ?? "";
    $captchaInput = trim($_POST["captcha_input"] ?? "");
    $captchaSession = $_SESSION["captcha"] ?? "";

    if ($captchaInput === "" || strcasecmp($captchaInput, $captchaSession) !== 0) {
        $_SESSION["login_error"] = "Kode captcha salah.";
        redirect_home();
    }

    $stmt = $koneksi->prepare("SELECT id, username, password, role FROM users WHERE LOWER(username)=LOWER(?) LIMIT 1");
    $stmt->bind_param("s", $username);
    $stmt->execute();
    $found = $stmt->get_result()->fetch_assoc();

    if (!$found || !password_verify($password, $found["password"])) {
        $_SESSION["login_attempts"]++;

        if ($_SESSION["login_attempts"] >= 3) {
            $_SESSION["lock_until"] = time() + 25;
            $_SESSION["login_error"] = "Terlalu banyak percobaan. Tunggu 25 detik.";
        } else {
            $sisa = 3 - $_SESSION["login_attempts"];
            $_SESSION["login_error"] = "Username atau password salah. Sisa kesempatan: {$sisa}.";
        }

        redirect_home();
    }

    $_SESSION["login_attempts"] = 0;
    $_SESSION["lock_until"] = 0;
    $_SESSION["user_id"] = $found["id"];
    $_SESSION["username"] = $found["username"];
    $_SESSION["role"] = $found["role"];
    unset($_SESSION["login_error"]);

    redirect_home();
}

/* Registrasi */
if ($_SERVER["REQUEST_METHOD"] === "POST" && ($_POST["action"] ?? "") === "register") {
    $username = trim($_POST["register_username"] ?? "");
    $password = $_POST["register_password"] ?? "";
    $confirm = $_POST["register_confirm"] ?? "";

    if ($username === "" || $password === "" || $confirm === "") {
        $_SESSION["register_error"] = "Semua kolom harus diisi.";
    } elseif (strlen($username) < 3) {
        $_SESSION["register_error"] = "Username minimal 3 karakter.";
    } elseif (strlen($password) < 6) {
        $_SESSION["register_error"] = "Password minimal 6 karakter.";
    } elseif ($password !== $confirm) {
        $_SESSION["register_error"] = "Konfirmasi password tidak sama.";
    } else {
        $check = $koneksi->prepare("SELECT id FROM users WHERE LOWER(username)=LOWER(?)");
        $check->bind_param("s", $username);
        $check->execute();

        if ($check->get_result()->num_rows > 0) {
            $_SESSION["register_error"] = "Username sudah digunakan.";
        } else {
            $hash = password_hash($password, PASSWORD_DEFAULT);
            $role = "user";
            $ins = $koneksi->prepare("INSERT INTO users (username,password,role) VALUES (?,?,?)");
            $ins->bind_param("sss", $username, $hash, $role);
            $ins->execute();
            $_SESSION["register_success"] = "Akun berhasil dibuat. Silakan login.";
        }
    }

    redirect_home();
}

$loggedIn = isset($_SESSION["user_id"]);
$role = $_SESSION["role"] ?? "";
$username = $_SESSION["username"] ?? "";

if ($loggedIn) {
    /* Tambah buku */
    if ($_SERVER["REQUEST_METHOD"] === "POST" && ($_POST["action"] ?? "") === "add_book" && $role === "admin") {
        $title = trim($_POST["title"] ?? "");
        $author = trim($_POST["author"] ?? "");
        $year = (int)($_POST["year"] ?? 0);
        $stock = (int)($_POST["stock"] ?? 0);

        if ($title && $author && $year > 0 && $stock >= 0) {
            $stmt = $koneksi->prepare("INSERT INTO books (title,author,year,stock) VALUES (?,?,?,?)");
            $stmt->bind_param("ssii", $title, $author, $year, $stock);
            $stmt->execute();
        }
        redirect_home();
    }

    /* Edit buku */
    if ($_SERVER["REQUEST_METHOD"] === "POST" && ($_POST["action"] ?? "") === "edit_book" && $role === "admin") {
        $id = (int)($_POST["id"] ?? 0);
        $title = trim($_POST["title"] ?? "");
        $author = trim($_POST["author"] ?? "");
        $year = (int)($_POST["year"] ?? 0);
        $stock = (int)($_POST["stock"] ?? 0);

        if ($id && $title && $author && $year > 0 && $stock >= 0) {
            $stmt = $koneksi->prepare("UPDATE books SET title=?,author=?,year=?,stock=? WHERE id=?");
            $stmt->bind_param("ssiii", $title, $author, $year, $stock, $id);
            $stmt->execute();
        }
        redirect_home();
    }

    /* Hapus buku */
    if (isset($_GET["delete_book"]) && $role === "admin") {
        $id = (int)$_GET["delete_book"];
        $stmt = $koneksi->prepare("DELETE FROM books WHERE id=?");
        $stmt->bind_param("i", $id);
        $stmt->execute();
        redirect_home();
    }

    /* Pinjam buku */
    if (isset($_GET["borrow_book"]) && $role === "user") {
        $bookId = (int)$_GET["borrow_book"];

        $koneksi->begin_transaction();
        try {
            $stmt = $koneksi->prepare("SELECT stock FROM books WHERE id=? FOR UPDATE");
            $stmt->bind_param("i", $bookId);
            $stmt->execute();
            $book = $stmt->get_result()->fetch_assoc();

            if ($book && $book["stock"] > 0) {
                $update = $koneksi->prepare("UPDATE books SET stock=stock-1 WHERE id=?");
                $update->bind_param("i", $bookId);
                $update->execute();

                $date = date("Y-m-d");
                $ins = $koneksi->prepare("INSERT INTO borrowings (user_id,book_id,date,status) VALUES (?,?,?,'Dipinjam')");
                $ins->bind_param("iis", $_SESSION["user_id"], $bookId, $date);
                $ins->execute();
            }

            $koneksi->commit();
        } catch (Exception $ex) {
            $koneksi->rollback();
        }
        redirect_home();
    }

    /* Kembalikan buku */
    if (isset($_GET["return_borrow"]) && $role === "user") {
        $borrowId = (int)$_GET["return_borrow"];

        $koneksi->begin_transaction();
        try {
            $stmt = $koneksi->prepare(
                "SELECT book_id FROM borrowings WHERE id=? AND user_id=? AND status='Dipinjam' FOR UPDATE"
            );
            $stmt->bind_param("ii", $borrowId, $_SESSION["user_id"]);
            $stmt->execute();
            $borrowing = $stmt->get_result()->fetch_assoc();

            if ($borrowing) {
                $updateBook = $koneksi->prepare("UPDATE books SET stock=stock+1 WHERE id=?");
                $updateBook->bind_param("i", $borrowing["book_id"]);
                $updateBook->execute();

                $updateBorrow = $koneksi->prepare("UPDATE borrowings SET status='Dikembalikan' WHERE id=?");
                $updateBorrow->bind_param("i", $borrowId);
                $updateBorrow->execute();
            }

            $koneksi->commit();
        } catch (Exception $ex) {
            $koneksi->rollback();
        }
        redirect_home();
    }
}

/* Data dashboard */
$totalBooks = 0;
$availableBooks = 0;
$borrowedBooks = 0;
$totalUsers = 0;
$books = [];
$borrowings = [];
$users = [];

if ($loggedIn) {
    $r = $koneksi->query("SELECT COUNT(*) AS n FROM books")->fetch_assoc();
    $totalBooks = (int)$r["n"];

    $r = $koneksi->query("SELECT COALESCE(SUM(stock),0) AS n FROM books")->fetch_assoc();
    $availableBooks = (int)$r["n"];

    $r = $koneksi->query("SELECT COUNT(*) AS n FROM borrowings WHERE status='Dipinjam'")->fetch_assoc();
    $borrowedBooks = (int)$r["n"];

    $r = $koneksi->query("SELECT COUNT(*) AS n FROM users")->fetch_assoc();
    $totalUsers = (int)$r["n"];

    $search = trim($_GET["search"] ?? "");
    if ($search !== "") {
        $like = "%" . $search . "%";
        $stmt = $koneksi->prepare("SELECT * FROM books WHERE title LIKE ? OR author LIKE ? ORDER BY id DESC");
        $stmt->bind_param("ss", $like, $like);
        $stmt->execute();
        $books = $stmt->get_result()->fetch_all(MYSQLI_ASSOC);
    } else {
        $books = $koneksi->query("SELECT * FROM books ORDER BY id DESC")->fetch_all(MYSQLI_ASSOC);
    }

    if ($role === "admin") {
        $borrowings = $koneksi->query(
            "SELECT b.id,b.date,b.status,u.username,bo.title
             FROM borrowings b
             JOIN users u ON u.id=b.user_id
             JOIN books bo ON bo.id=b.book_id
             ORDER BY b.id DESC"
        )->fetch_all(MYSQLI_ASSOC);

        $users = $koneksi->query("SELECT id,username,role FROM users ORDER BY id ASC")->fetch_all(MYSQLI_ASSOC);
    } else {
        $stmt = $koneksi->prepare(
            "SELECT b.id,b.date,b.status,u.username,bo.title
             FROM borrowings b
             JOIN users u ON u.id=b.user_id
             JOIN books bo ON bo.id=b.book_id
             WHERE b.user_id=?
             ORDER BY b.id DESC"
        );
        $stmt->bind_param("i", $_SESSION["user_id"]);
        $stmt->execute();
        $borrowings = $stmt->get_result()->fetch_all(MYSQLI_ASSOC);
    }
}

/* Captcha */
$captchaChars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
$captcha = "";
for ($i=0; $i<5; $i++) {
    $captcha .= $captchaChars[random_int(0, strlen($captchaChars)-1)];
}
$_SESSION["captcha"] = $captcha;
?>
<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Sistem Perpustakaan</title>
<style>
:root{
  --primary:#2563eb;
  --primary-dark:#1d4ed8;
  --secondary:#14b8a6;
  --bg:#f5f7fb;
  --card:#ffffff;
  --text:#0f172a;
  --muted:#64748b;
  --border:#e2e8f0;
  --danger:#dc2626;
  --success:#16a34a;
  --warning:#f59e0b;
  --shadow:0 10px 30px rgba(15,23,42,.08);
  --radius:18px;
}
*{box-sizing:border-box}
html{scroll-behavior:smooth}
body{
  margin:0;
  font-family:Inter,Segoe UI,Arial,sans-serif;
  background:var(--bg);
  color:var(--text);
  line-height:1.5;
}
button,input{font:inherit}
a{transition:.2s ease}

/* LOGIN */
#loginPage{
  min-height:100vh;
  display:flex;
  align-items:center;
  justify-content:center;
  padding:24px;
  background:
    radial-gradient(circle at 10% 20%,rgba(255,255,255,.18),transparent 30%),
    radial-gradient(circle at 90% 80%,rgba(255,255,255,.14),transparent 30%),
    linear-gradient(135deg,#1d4ed8 0%,#2563eb 45%,#0f766e 100%);
}
.login-box{
  width:min(430px,100%);
  background:rgba(255,255,255,.97);
  padding:34px;
  border-radius:24px;
  box-shadow:0 25px 70px rgba(0,0,0,.22);
  border:1px solid rgba(255,255,255,.5);
}
.login-brand{text-align:center;margin-bottom:26px}
.logo{
  width:68px;height:68px;margin:0 auto 14px;
  display:grid;place-items:center;
  border-radius:20px;
  background:linear-gradient(135deg,var(--primary),var(--secondary));
  color:#fff;font-size:32px;
  box-shadow:0 12px 25px rgba(37,99,235,.25);
}
.login-box h1{margin:0;font-size:27px}
.subtitle{margin:6px 0 0;color:var(--muted);font-size:14px}
.form-group{margin-bottom:15px}
label{display:block;margin-bottom:7px;font-weight:700;font-size:13px}
.input-wrap{position:relative}
input,select{
  width:100%;
  padding:13px 14px;
  border:1px solid var(--border);
  border-radius:12px;
  background:#fff;
  color:var(--text);
  outline:none;
  transition:.2s;
}
input:focus,select:focus{
  border-color:var(--primary);
  box-shadow:0 0 0 4px rgba(37,99,235,.10);
}
.captcha-box{display:flex;align-items:center;gap:10px;margin-bottom:9px}
.captcha-code{
  flex:1;
  background:#eef2ff;
  color:#1e3a8a;
  font-size:21px;font-weight:800;letter-spacing:5px;
  text-align:center;padding:11px;border-radius:12px;
  user-select:none;font-family:'Courier New',monospace;
  text-decoration:line-through;
}
.refresh-btn{
  width:48px;height:46px;padding:0;
  background:#0f172a;color:white;border-radius:12px;
}
.refresh-btn:hover{background:#1e293b;transform:rotate(-8deg)}
.login-btn,.register-btn{
  width:100%;padding:13px 16px;border-radius:12px;
  font-weight:800;cursor:pointer;
}
.login-btn{
  border:0;background:linear-gradient(135deg,var(--primary),#3b82f6);
  color:#fff;box-shadow:0 8px 18px rgba(37,99,235,.22);
}
.login-btn:hover{background:var(--primary-dark);transform:translateY(-1px)}
.register-btn{
  margin-top:10px;border:1px solid #bfdbfe;
  background:#eff6ff;color:var(--primary);
}
.register-btn:hover{background:#dbeafe}
.error,.success{
  padding:11px 13px;border-radius:11px;text-align:center;
  margin:0 0 16px;font-size:13px;font-weight:600;
}
.error{color:#b91c1c;background:#fef2f2;border:1px solid #fecaca}
.success{color:#15803d;background:#f0fdf4;border:1px solid #bbf7d0}
.demo{
  margin-top:20px;padding:14px;border-radius:13px;
  background:#f8fafc;border:1px solid var(--border);
  font-size:13px;color:var(--muted);
}
.demo b{color:var(--text)}

/* SIDEBAR */
.sidebar{
  width:250px;height:100vh;position:fixed;left:0;top:0;
  background:linear-gradient(180deg,#0f172a,#111827);
  color:#fff;padding:22px 16px;z-index:50;
  box-shadow:8px 0 25px rgba(15,23,42,.08);
}
.brand{
  display:flex;align-items:center;gap:11px;
  padding:6px 9px 25px;border-bottom:1px solid rgba(255,255,255,.08);
  margin-bottom:20px;
}
.brand-icon{
  width:42px;height:42px;border-radius:12px;
  display:grid;place-items:center;
  background:linear-gradient(135deg,var(--primary),var(--secondary));
  font-size:20px;
}
.brand h2{font-size:17px;margin:0}
.brand small{color:#94a3b8;font-size:11px}
.sidebar a{
  display:flex;align-items:center;gap:10px;
  width:100%;margin:5px 0;
  color:#cbd5e1;text-decoration:none;
  padding:12px 13px;border-radius:11px;
  font-size:14px;font-weight:600;
}
.sidebar a:hover,.sidebar a.active{background:#1e293b;color:#fff}
.logout{margin-top:22px!important;background:rgba(220,38,38,.12)!important;color:#fca5a5!important}
.logout:hover{background:var(--danger)!important;color:#fff!important}

/* MAIN */
.main{margin-left:250px;padding:28px;min-height:100vh}
.header{
  display:flex;justify-content:space-between;align-items:center;gap:20px;
  background:var(--card);padding:23px 25px;border-radius:var(--radius);
  margin-bottom:22px;box-shadow:var(--shadow);border:1px solid var(--border);
}
.header h1{margin:0;font-size:26px}
.header p{margin:5px 0 0;color:var(--muted);font-size:14px}
.user-badge{
  background:#eff6ff;color:var(--primary);
  padding:9px 13px;border-radius:999px;font-size:13px;font-weight:700;
}
.stats{
  display:grid;grid-template-columns:repeat(4,1fr);
  gap:16px;margin-bottom:22px;
}
.stat{
  position:relative;overflow:hidden;
  background:var(--card);padding:20px;border-radius:var(--radius);
  box-shadow:var(--shadow);border:1px solid var(--border);
}
.stat:after{
  content:"";position:absolute;right:-25px;bottom:-35px;
  width:90px;height:90px;border-radius:50%;
  background:rgba(37,99,235,.07);
}
.stat h3{margin:0;color:var(--muted);font-size:13px;font-weight:700}
.stat p{font-size:30px;font-weight:800;margin:7px 0 0}
.stat-icon{font-size:24px;margin-bottom:8px}
.content{
  background:var(--card);padding:23px;border-radius:var(--radius);
  box-shadow:var(--shadow);border:1px solid var(--border);
  margin-bottom:20px;overflow:hidden;
}
.content h2{margin:0 0 18px;font-size:19px}
.section-head{
  display:flex;align-items:center;justify-content:space-between;
  gap:15px;margin-bottom:17px;
}
.search-row{display:flex;gap:10px;margin-bottom:17px}
.search{max-width:360px!important;margin:0!important}
.add-btn{
  background:var(--success);color:white;margin:0;
  border:0;padding:12px 16px;border-radius:11px;font-weight:700;
}
.add-btn:hover{background:#15803d}
.book-form{
  display:grid;grid-template-columns:2fr 1.5fr .9fr .8fr auto;
  gap:10px;margin-bottom:18px;padding:15px;
  background:#f8fafc;border:1px solid var(--border);border-radius:14px;
}
.book-form input{margin:0}

/* TABLE */
.table-wrap{overflow-x:auto}
table{width:100%;border-collapse:separate;border-spacing:0;min-width:650px}
th,td{padding:14px 13px;border-bottom:1px solid var(--border);text-align:left}
th{
  background:#f8fafc;color:#475569;font-size:12px;
  text-transform:uppercase;letter-spacing:.04em;
}
th:first-child{border-radius:10px 0 0 10px}
th:last-child{border-radius:0 10px 10px 0}
tbody tr:hover{background:#f8fafc}
td{font-size:14px}
.actions{display:flex;gap:6px;flex-wrap:wrap}
.edit,.delete,.borrow,.return{
  padding:8px 11px!important;border-radius:8px;
  text-decoration:none;display:inline-block;font-size:12px;font-weight:700;
}
.edit{background:#f59e0b;color:white}
.delete{background:var(--danger);color:white}
.borrow{background:var(--primary);color:white}
.return{background:var(--success);color:white}
.edit:hover,.delete:hover,.borrow:hover,.return:hover{filter:brightness(.92)}
.status{
  display:inline-block;padding:5px 9px;border-radius:999px;
  font-size:11px;font-weight:800;
}
.status-dipinjam{background:#dbeafe;color:#1d4ed8}
.status-dikembalikan{background:#dcfce7;color:#15803d}

/* MODAL */
.modal{
  display:flex;position:fixed;inset:0;
  background:rgba(15,23,42,.62);backdrop-filter:blur(4px);
  justify-content:center;align-items:center;padding:20px;z-index:999;
}
.modal-box{
  background:white;width:min(460px,100%);
  padding:26px;border-radius:20px;
  box-shadow:0 25px 70px rgba(0,0,0,.25);
}
.modal-box h2{margin:0 0 20px}
.modal-box input{margin:0 0 14px}
.save,.cancel{
  padding:11px 15px;border:0;border-radius:10px;
  font-weight:700;cursor:pointer;text-decoration:none;
}
.save{background:var(--primary);color:white}
.cancel{background:#64748b;color:white;margin-left:5px}

/* MOBILE */
.mobile-menu{display:none}
@media(max-width:1050px){
  .stats{grid-template-columns:repeat(2,1fr)}
  .book-form{grid-template-columns:1fr 1fr}
  .book-form button{grid-column:1/-1}
}
@media(max-width:800px){
  .sidebar{
    width:100%;height:auto;position:relative;
    padding:12px;box-shadow:none;
  }
  .brand{padding:5px 8px 12px;margin-bottom:8px}
  .sidebar nav{display:flex;overflow-x:auto;gap:5px}
  .sidebar a{white-space:nowrap;width:auto;margin:0}
  .logout{margin-top:0!important}
  .main{margin-left:0;padding:16px}
  .header{padding:19px;align-items:flex-start}
  .header h1{font-size:22px}
}
@media(max-width:600px){
  #loginPage{padding:15px}
  .login-box{padding:24px 20px;border-radius:20px}
  .stats{grid-template-columns:1fr 1fr;gap:10px}
  .stat{padding:15px}
  .stat p{font-size:24px}
  .content{padding:17px}
  .section-head{align-items:flex-start;flex-direction:column}
  .search-row{display:block}
  .search{max-width:none!important}
  .book-form{grid-template-columns:1fr}
  .book-form button{grid-column:auto}
  .header{display:block}
  .user-badge{display:inline-block;margin-top:12px}
}
</style>
</head>
<body>

<?php if (!$loggedIn): ?>
<div id="loginPage">
<div class="login-box">
<div class="login-brand">
<div class="logo">📚</div>
<h1>Perpustakaan</h1>
<p class="subtitle">Masuk untuk mengakses sistem perpustakaan</p>
</div>

<?php if (!empty($_SESSION["login_error"])): ?>
<div class="error"><?=e($_SESSION["login_error"]); unset($_SESSION["login_error"]);?></div>
<?php endif; ?>

<?php if (!empty($_SESSION["register_success"])): ?>
<div class="success"><?=e($_SESSION["register_success"]); unset($_SESSION["register_success"]);?></div>
<?php endif; ?>

<form method="post">
<input type="hidden" name="action" value="login">
<div class="form-group"><label>Username</label>
<input type="text" name="username" placeholder="Masukkan username" required></div>
<div class="form-group"><label>Password</label>
<input type="password" name="password" placeholder="Masukkan password" required></div>
<div class="form-group"><label>Kode Captcha</label>
<div class="captcha-box">
<div class="captcha-code"><?=e($captcha)?></div>
<button class="refresh-btn" type="button" onclick="location.reload()">🔄</button>
</div>
<input type="text" name="captcha_input" placeholder="Masukkan captcha di atas" required></div>
<button class="login-btn" type="submit">Login</button>
</form>

<button class="register-btn" onclick="document.getElementById('registerModal').style.display='flex'">➕ Buat Akun Baru</button>

<div class="demo">
Admin: <b>admin</b> / <b>admin123</b><br>
User: <b>habil</b> / <b>habil123</b>
</div>
</div>
</div>

<div class="modal" id="registerModal" style="display:<?=isset($_SESSION["register_error"]) ? "flex" : "none"?>">
<div class="modal-box">
<h2>👤 Buat Akun Baru</h2>
<?php if (!empty($_SESSION["register_error"])): ?>
<div class="error"><?=e($_SESSION["register_error"]); unset($_SESSION["register_error"]);?></div>
<?php endif; ?>
<form method="post">
<input type="hidden" name="action" value="register">
<label>Username</label>
<input name="register_username" type="text" required>
<label>Password</label>
<input name="register_password" type="password" required>
<label>Konfirmasi Password</label>
<input name="register_confirm" type="password" required>
<button class="save" type="submit">Daftar</button>
<button class="cancel" type="button" onclick="document.getElementById('registerModal').style.display='none'">Batal</button>
</form>
</div>
</div>

<?php else: ?>

<div class="sidebar">
<div class="brand">
  <div class="brand-icon">📚</div>
  <div><h2>Perpustakaan</h2><small>Sistem Manajemen</small></div>
</div>
<nav>
<a href="index.php">🏠 Dashboard</a>
<a href="index.php#books">📖 Data Buku</a>
<a href="index.php#borrow">📋 Peminjaman</a>
<?php if ($role === "admin"): ?><a href="index.php#users">👥 Data User</a><?php endif; ?>
<a class="logout" href="index.php?logout=1">🚪 Logout</a>
</nav>
</div>

<div class="main">
<div class="header">
<div><h1>Dashboard</h1>
<p>Selamat datang kembali, <b><?=e($username)?></b></p></div>
<div class="user-badge"><?=e(strtoupper($role))?></div>
</div>

<div class="stats">
<div class="stat"><div class="stat-icon">📚</div><h3>Total Buku</h3><p><?=$totalBooks?></p></div>
<div class="stat"><div class="stat-icon">📗</div><h3>Buku Tersedia</h3><p><?=$availableBooks?></p></div>
<div class="stat"><div class="stat-icon">📖</div><h3>Sedang Dipinjam</h3><p><?=$borrowedBooks?></p></div>
<div class="stat"><div class="stat-icon">👥</div><h3>Total User</h3><p><?=$totalUsers?></p></div>
</div>

<div class="content" id="books">
<h2>📖 Data Buku</h2>

<?php if ($role === "admin"): ?>
<form method="post" class="book-form">
<input type="hidden" name="action" value="add_book">
<input name="title" placeholder="Judul buku" required>
<input name="author" placeholder="Penulis" required>
<input name="year" type="number" placeholder="Tahun" required>
<input name="stock" type="number" min="0" placeholder="Stok" required>
<button class="add-btn" type="submit">+ Tambah Buku</button>
</form>
<?php endif; ?>

<form method="get">
<input class="search" name="search" value="<?=e($_GET["search"] ?? "")?>" placeholder="🔎 Cari judul atau penulis...">
</form>

<table>
<thead><tr><th>No</th><th>Judul</th><th>Penulis</th><th>Tahun</th><th>Stok</th><th>Aksi</th></tr></thead>
<tbody>
<?php foreach($books as $i=>$book): ?>
<tr>
<td><?=$i+1?></td>
<td><?=e($book["title"])?></td>
<td><?=e($book["author"])?></td>
<td><?=e($book["year"])?></td>
<td><?=e($book["stock"])?></td>
<td>
<?php if ($role === "admin"): ?>
<div class="actions"><a class="edit" href="?edit=<?=$book["id"]?>">Edit</a>
<a class="delete" style="padding:8px;text-decoration:none;display:inline-block" href="?delete_book=<?=$book["id"]?>" onclick="return confirm('Yakin ingin menghapus buku?')">Hapus</a></div>
<?php elseif ((int)$book["stock"] > 0): ?>
<div class="actions"><a class="borrow" href="?borrow_book=<?=$book["id"]?>" onclick="return confirm('Pinjam buku ini?')">Pinjam</a></div>
<?php else: ?>Stok habis<?php endif; ?>
</td>
</tr>
<?php endforeach; ?>
</tbody>
</table></div>
</div>

<div class="content" id="borrow" style="margin-top:20px">
<h2>📋 Data Peminjaman</h2>
<table>
<thead><tr><th>No</th><th>User</th><th>Buku</th><th>Tanggal</th><th>Status</th><th>Aksi</th></tr></thead>
<tbody>
<?php foreach($borrowings as $i=>$b): ?>
<tr>
<td><?=$i+1?></td><td><?=e($b["username"])?></td><td><?=e($b["title"])?></td>
<td><?=e($b["date"])?></td><td><?=e($b["status"])?></td>
<td>
<?php if ($role === "user" && $b["status"] === "Dipinjam"): ?>
<div class="actions"><a class="return" href="?return_borrow=<?=$b["id"]?>" onclick="return confirm('Kembalikan buku ini?')">Kembalikan</a></div>
<?php endif; ?>
</td>
</tr>
<?php endforeach; ?>
</tbody>
</table></div>
</div>

<?php if ($role === "admin"): ?>
<div class="content" id="users" style="margin-top:20px">
<h2>👥 Data User</h2>
<table>
<thead><tr><th>No</th><th>Username</th><th>Role</th></tr></thead>
<tbody>
<?php foreach($users as $i=>$u): ?>
<tr><td><?=$i+1?></td><td><?=e($u["username"])?></td><td><?=e($u["role"])?></td></tr>
<?php endforeach; ?>
</tbody>
</table></div>
</div>
<?php endif; ?>

</div>
<?php endif; ?>

<?php
/* Modal edit buku */
if ($loggedIn && $role === "admin" && isset($_GET["edit"])):
$id = (int)$_GET["edit"];
$stmt = $koneksi->prepare("SELECT * FROM books WHERE id=?");
$stmt->bind_param("i",$id);
$stmt->execute();
$edit = $stmt->get_result()->fetch_assoc();
if ($edit):
?>
<div class="modal">
<div class="modal-box">
<h2>✏️ Edit Buku</h2>
<form method="post">
<input type="hidden" name="action" value="edit_book">
<input type="hidden" name="id" value="<?=$edit["id"]?>">
<label>Judul</label><input name="title" value="<?=e($edit["title"])?>" required>
<label>Penulis</label><input name="author" value="<?=e($edit["author"])?>" required>
<label>Tahun</label><input name="year" type="number" value="<?=e($edit["year"])?>" required>
<label>Stok</label><input name="stock" type="number" min="0" value="<?=e($edit["stock"])?>" required>
<button class="save" type="submit">Simpan</button>
<a class="cancel" style="padding:11px 15px;text-decoration:none;display:inline-block" href="index.php">Batal</a>
</form>
</div>
</div>
<?php endif; endif; ?>

<script>
if (location.hash) {
    setTimeout(() => {
        const el = document.querySelector(location.hash);
        if (el) el.scrollIntoView({behavior:"smooth"});
    }, 100);
}
</script>
</body>
</html>