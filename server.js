const express = require("express");
const session = require("express-session");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const path = require("path");

const app = express();

const PORT = process.env.PORT || 3000;
const SESSION_SECRET = process.env.SESSION_SECRET || "dev_session_secret";
const JWT_SECRET = process.env.JWT_SECRET || "dev_jwt_secret";

app.use(express.json());
app.use(cookieParser());

app.use(
  session({
    name: "connect.sid",
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: false,
      maxAge: 1000 * 60 * 60,
    },
  })
);

app.use(express.static(path.join(__dirname, "public")));

const users = new Map(); // username -> { username, password }

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
    req.jwtUser = decoded;
    next();
  } catch {
    return res.status(401).json({ error: "Invalid/expired token" });
  }
}

// ---- Session
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

  req.session.user = { username: u.username };
  res.json({ ok: true, note: "Session login OK (server remembers you)" });
});

app.get("/session/me", (req, res) => {
  const user = req.session.user || null;
  if (!user) return res.status(401).json({ error: "Not logged in (session)" });
  res.json({ ok: true, user, note: "Cookie(connect.sid) -> server session -> user" });
});

app.post("/session/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) return res.status(500).json({ error: "Failed to destroy session" });
    res.clearCookie("connect.sid");
    res.json({ ok: true });
  });
});

// ---- JWT
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

  const token = signJwt({ username: u.username });
  res.json({ ok: true, token, note: "JWT login OK (server gives you a card)" });
});

app.get("/jwt/me", authJwt, (req, res) => {
  res.json({ ok: true, user: { username: req.jwtUser.username }, note: "Authorization: Bearer <token> required" });
});

app.post("/jwt/logout", (req, res) => {
  res.json({ ok: true, note: "JWT logout = delete token on client" });
});

// ---- Debug (見える化)
app.get("/debug", (req, res) => {
  const cookieSid = req.cookies["connect.sid"] || null;
  const auth = req.headers.authorization || null;

  res.json({
    browser_sends: {
      cookie_connect_sid: cookieSid ? "(present)" : "(none)",
      authorization_header: auth ? "(present)" : "(none)",
    },
    server_state: {
      sessionId: req.sessionID || null,
      sessionUser: req.session?.user || null,
    },
    raw: {
      cookies: req.cookies,
      authorization: auth,
    },
  });
});

app.listen(PORT, () => console.log(`Server running: http://localhost:${PORT}`));
