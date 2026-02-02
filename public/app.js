function $(id) { return document.getElementById(id); }

async function api(path, opts = {}) {
  const res = await fetch(path, {
    headers: { "Content-Type": "application/json", ...(opts.headers || {}) },
    credentials: "include", // ← Session: Cookie送受信のため重要（JWTでも害はない）
    ...opts,
  });
  const text = await res.text();
  let data;
  try { data = JSON.parse(text); } catch { data = { raw: text }; }
  return { status: res.status, data };
}

function show(preId, obj) {
  $(preId).textContent = JSON.stringify(obj, null, 2);
}

// ---- Session
async function sessionRegister() {
  const r = await api("/session/register", {
    method: "POST",
    body: JSON.stringify({ username: $("s_user").value, password: $("s_pass").value }),
  });
  show("s_out", r);
}
async function sessionLogin() {
  const r = await api("/session/login", {
    method: "POST",
    body: JSON.stringify({ username: $("s_user").value, password: $("s_pass").value }),
  });
  show("s_out", r);
}
async function sessionMe() {
  const r = await api("/session/me");
  show("s_out", r);
}
async function sessionLogout() {
  const r = await api("/session/logout", { method: "POST" });
  show("s_out", r);
}

// ---- JWT
function setToken(t) {
  if (t) localStorage.setItem("demo_jwt", t);
  else localStorage.removeItem("demo_jwt");
  $("token_state").textContent = localStorage.getItem("demo_jwt") ? "(stored)" : "(none)";
}
setToken(localStorage.getItem("demo_jwt"));

async function jwtRegister() {
  const r = await api("/jwt/register", {
    method: "POST",
    body: JSON.stringify({ username: $("j_user").value, password: $("j_pass").value }),
  });
  show("j_out", r);
}

async function jwtLogin() {
  const r = await api("/jwt/login", {
    method: "POST",
    body: JSON.stringify({ username: $("j_user").value, password: $("j_pass").value }),
  });
  if (r.data && r.data.token) setToken(r.data.token);
  show("j_out", r);
}

async function jwtMe() {
  const token = localStorage.getItem("demo_jwt");
  const r = await api("/jwt/me", {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
  show("j_out", r);
}

async function jwtLogout() {
  // JWTは「サーバ側に消す状態がない」ので token を捨てる
  setToken(null);
  const r = await api("/jwt/logout", { method: "POST" });
  show("j_out", r);
}

// ---- Debug
async function debug() {
  const token = localStorage.getItem("demo_jwt");
  const r = await api("/debug", {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
  show("d_out", r);
}
