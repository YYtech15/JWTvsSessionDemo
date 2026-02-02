const express = require("express");
const session = require("express-session");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const path = require("path");

const app = express();

const PORT = process.env.PORT || 3000;
const SESSION_SECRET = process.env.SESSION_SECRET || "dev_session_secret";
const JWT_SECRET = process.env.JWT_SECRET || "dev_jwt_secret";

// --- Middleware
app.use(express.json());
app.use(cookieParser());

// Session (Cookie-based)
app.use(
  session({
    name: "connect.sid",
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      // 本番で https のとき true
      secure: false,
      maxAge: 1000 * 60 * 60, // 1h
    },
  })
);

// Static files
app.use(express.static(path.join(__dirname, "public")));

// --- In-memory user store (学習用)
const users = new Map(); // username -> { username, password }

// --- Helpers
function safeUser(u) {
  return u ? { username: u.username } : null;
}

function signJwt(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: "1h" });
}

function authJwt(req, res, next) {
  const h = req.headers.authorization || "";
  const [type, token] = h.split(" ");
  if (type !== "Bearer" || !token) {
    return res.status(401).json({ error: "Missing Bearer token" });
  }
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.jwtUser = decoded; // { username, iat, exp }
    next();
  } catch (e) {
    return res.status(401).json({ error: "Invalid/expired token" });
  }
}

// =========================
// Session auth routes
// =========================
app.post("/session/register", (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: "username/password required" });
  if (users.has(username)) return res.status(409).json({ error: "User already exists" });
  users.set(username, { username, password });
  res.json({ ok: true, user: { username } });
});

app.post("/session/login", (req, res) => {
  const { username, password } = req.body || {};
  const u = users.get(username);
  if (!u || u.password !== password) return res.status(401).json({ error: "Invalid credentials" });

  req.session.user = { username: u.username }; // ← サーバ側に「ログイン状態」が残る
  res.json({ ok: true, user: safeUser(u) });
});

app.get("/session/me", (req, res) => {
  // Cookie(connect.sid) → サーバで session を引いて user を返す
  const user = req.session.user || null;
  if (!user) return res.status(401).json({ error: "Not logged in (session)" });
  res.json({ ok: true, user });
});

app.post("/session/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) return res.status(500).json({ error: "Failed to destroy session" });
    res.clearCookie("connect.sid");
    res.json({ ok: true });
  });
});

// =========================
// JWT auth routes
// =========================
app.post("/jwt/register", (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: "username/password required" });
  if (users.has(username)) return res.status(409).json({ error: "User already exists" });
  users.set(username, { username, password });
  res.json({ ok: true, user: { username } });
});

app.post("/jwt/login", (req, res) => {
  const { username, password } = req.body || {};
  const u = users.get(username);
  if (!u || u.password !== password) return res.status(401).json({ error: "Invalid credentials" });

  // ← サーバは状態を保持せず「トークン」を返すだけ
  const token = signJwt({ username: u.username });
  res.json({ ok: true, token, user: safeUser(u) });
});

app.get("/jwt/me", authJwt, (req, res) => {
  // Authorization: Bearer <token> を毎回送る
  res.json({ ok: true, user: { username: req.jwtUser.username } });
});

app.post("/jwt/logout", (req, res) => {
  // JWTは基本「サーバ側ログアウト」がない（状態を持たない）
  // → クライアント側で token を捨てるのが基本
  res.json({ ok: true, note: "JWT logout = delete token on client (unless you implement blacklist/rotation)" });
});

// --- Debug endpoint（Cookieやheaders確認）
app.get("/debug", (req, res) => {
  res.json({
    cookies: req.cookies,
    sessionId: req.sessionID,
    sessionUser: req.session.user || null,
    authorization: req.headers.authorization || null,
  });
});

app.listen(PORT, () => {
  console.log(`Server running: http://localhost:${PORT}`);
});
