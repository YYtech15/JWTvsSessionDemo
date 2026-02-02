function $(id) { return document.getElementById(id); }

let lastAuthSent = "(none)";

async function api(path, opts = {}) {
  const res = await fetch(path, {
    headers: { "Content-Type": "application/json", ...(opts.headers || {}) },
    credentials: "include", // SessionのCookie送受信に必要
    ...opts,
  });

  const text = await res.text();
  let data;
  try { data = JSON.parse(text); } catch { data = { raw: text }; }

  return { status: res.status, data };
}

function show(obj) {
  $("out").textContent = JSON.stringify(obj, null, 2);
}

function setToken(t) {
  if (t) localStorage.setItem("demo_jwt", t);
  else localStorage.removeItem("demo_jwt");
}

function refreshStates() {
  $("token_state").textContent = localStorage.getItem("demo_jwt") ? "(present)" : "(none)";
  $("auth_state").textContent = lastAuthSent;
}

function updateLoginState(debugData) {
  const el = $("loginState");
  const hasSession = debugData?.server_state?.sessionUser !== null;
  const hasJwt = localStorage.getItem("demo_jwt") !== null;

  if (hasSession) {
    el.textContent = "今の状態：Sessionログイン中";
    el.style.background = "#dbeafe";
  } else if (hasJwt) {
    el.textContent = "今の状態：JWTログイン中";
    el.style.background = "#dcfce7";
  } else {
    el.textContent = "今の状態：未ログイン";
    el.style.background = "#f3f4f6";
  }
}

async function debugAndShow(note) {
  const token = localStorage.getItem("demo_jwt");
  const headers = token ? { Authorization: `Bearer ${token}` } : {};

  lastAuthSent = token ? "Bearer (sent)" : "(none)";
  refreshStates();

  const r = await api("/debug", { headers });

  $("cookie_state").textContent =
    r.data?.browser_sends?.cookie_connect_sid || "?";

  updateLoginState(r.data);

  show({ note, debug: r });
}

// 初期表示
refreshStates();
debugAndShow("最初の状態（まだ何もしてない）");

// --------------------
// 追加：登録ボタン
// --------------------
async function sessionRegister() {
  const username = $("user").value;
  const password = $("pass").value;

  const r = await api("/session/register", {
    method: "POST",
    body: JSON.stringify({ username, password }),
  });

  await debugAndShow("Session登録を押した後（登録できた？）");
  show({ action: "sessionRegister", result: r, hint: "409なら『もう登録済み』なのでOKです", after_debug: JSON.parse($("out").textContent).debug });
}

async function jwtRegister() {
  const username = $("user").value;
  const password = $("pass").value;

  const r = await api("/jwt/register", {
    method: "POST",
    body: JSON.stringify({ username, password }),
  });

  await debugAndShow("JWT登録を押した後（登録できた？）");
  show({ action: "jwtRegister", result: r, hint: "409なら『もう登録済み』なのでOKです", after_debug: JSON.parse($("out").textContent).debug });
}

// --------------------
// ログイン→確認（授業向けの流れ）
// --------------------
async function sessionLoginAndCheck() {
  const username = $("user").value;
  const password = $("pass").value;

  const login = await api("/session/login", {
    method: "POST",
    body: JSON.stringify({ username, password }),
  });

  const me = await api("/session/me"); // Cookieで通るはず

  await debugAndShow("Sessionログイン→確認後（Cookieが送られている？）");
  show({
    action: "sessionLoginAndCheck",
    login,
    me,
    note: "SessionはCookie(connect.sid)が勝手に送られる",
    debug: JSON.parse($("out").textContent).debug,
  });
}

async function jwtLoginAndCheck() {
  const username = $("user").value;
  const password = $("pass").value;

  const login = await api("/jwt/login", {
    method: "POST",
    body: JSON.stringify({ username, password }),
  });

  if (login.data?.token) setToken(login.data.token);

  const token = localStorage.getItem("demo_jwt");
  const me = await api("/jwt/me", {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });

  await debugAndShow("JWTログイン→確認後（Authorizationが送られている？）");
  show({
    action: "jwtLoginAndCheck",
    login: { status: login.status, hasToken: !!login.data?.token },
    me,
    note: "JWTはAuthorization: Bearer <token> がないと通れない",
    debug: JSON.parse($("out").textContent).debug,
  });
}

// --------------------
// リセット＆/debugだけ
// --------------------
async function resetAll() {
  await api("/session/logout", { method: "POST" });
  setToken(null);

  lastAuthSent = "(none)";
  refreshStates();

  await debugAndShow("リセット後：CookieもTokenもない状態に戻る");
}

async function debugOnly() {
  await debugAndShow("/debug だけ確認（持ち物チェック用）");
}
