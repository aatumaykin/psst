"use strict";

const $ = (id) => document.getElementById(id);
let currentSecret = null;
let editing = false;

async function api(method, path, body) {
  const opts = { method, headers: {} };
  if (body !== undefined) {
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(body);
  }
  const res = await fetch(path, opts);
  let data = {};
  try { data = await res.json(); } catch (_) {}
  if (res.status === 401) { showView("login"); throw new Error(data.error || "not authenticated"); }
  if (!res.ok) {
    if (data.reunlock) { state.unlocked = false; openUnlock(); }
    throw new Error(data.error || ("HTTP " + res.status));
  }
  return data;
}

const state = { authenticated: false, unlocked: false, verified: false, unlockExpiresAt: null };

function showView(name) {
  for (const v of ["login", "list", "history", "form"]) $("view-" + v).hidden = v !== name;
}

function fmtDate(iso) {
  if (!iso) return "";
  return new Date(iso).toLocaleString();
}

function renderUnlockState() {
  const el = $("unlock-state");
  $("btn-unlock").hidden = state.unlocked;
  if (state.unlocked) {
    const left = Math.max(0, Math.floor((new Date(state.unlockExpiresAt) - Date.now()) / 60000));
    el.textContent = state.verified ? "unlocked (" + left + " min left)" : "unlocked (unverified — vault is empty)";
  } else {
    el.textContent = state.authenticated ? "locked" : "";
  }
  $("btn-logout").hidden = !state.authenticated;
}

function openUnlock(note) {
  $("unlock-note").hidden = !note;
  if (note) $("unlock-note").textContent = note;
  $("modal-unlock").hidden = false;
  $("unlock-password").value = "";
  $("unlock-password").focus();
}

async function refreshSession() {
  const s = await api("GET", "/api/session");
  state.authenticated = s.authenticated;
  state.unlocked = s.unlocked;
  state.verified = s.verified;
  state.unlockExpiresAt = s.unlockExpiresAt;
  showView(s.authenticated ? "list" : "login");
  renderUnlockState();
  if (s.authenticated) await loadList();
}

async function loadList() {
  const data = await api("GET", "/api/secrets");
  $("sync-warning").hidden = !data.warning;
  if (data.warning) $("sync-warning").textContent = data.warning;
  const tree = $("secret-tree");
  tree.textContent = "";
  const groups = new Map();
  for (const sec of data.secrets) {
    const tag = sec.tags && sec.tags.length ? sec.tags[0] : "untagged";
    if (!groups.has(tag)) groups.set(tag, []);
    groups.get(tag).push(sec);
  }
  const sorted = [...groups.keys()].sort();
  for (const tag of sorted) {
    const g = document.createElement("div");
    g.className = "group";
    const h = document.createElement("h3");
    h.textContent = tag;
    g.appendChild(h);
    for (const sec of groups.get(tag)) {
      const row = document.createElement("div");
      row.className = "secret-row";
      const name = document.createElement("span");
      name.className = "name";
      name.textContent = sec.name;
      name.addEventListener("click", () => openHistory(sec.name));
      const meta = document.createElement("span");
      meta.className = "meta";
      meta.textContent = fmtDate(sec.updatedAt) + (sec.updatedBy ? " · " + sec.updatedBy : "");
      row.appendChild(name);
      row.appendChild(meta);
      g.appendChild(row);
    }
    tree.appendChild(g);
  }
}

async function openHistory(name) {
  currentSecret = name;
  $("reveal-box").hidden = true;
  $("reveal-note").hidden = true;
  const data = await api("GET", "/api/secrets/" + name + "/history");
  $("history-title").textContent = name;
  const body = $("history-body");
  body.textContent = "";
  for (const h of data.history) {
    const tr = document.createElement("tr");
    for (const val of [String(h.version), fmtDate(h.archivedAt), h.author, (h.tags && h.tags[0]) || ""]) {
      const td = document.createElement("td");
      td.textContent = val;
      tr.appendChild(td);
    }
    const act = document.createElement("td");
    const btn = document.createElement("button");
    btn.className = "ghost";
    btn.textContent = "rollback";
    btn.disabled = !state.unlocked;
    btn.addEventListener("click", async () => {
      try {
        await api("POST", "/api/secrets/" + name + "/rollback", { version: h.version });
        await openHistory(name);
      } catch (e) { alert(e.message); }
    });
    act.appendChild(btn);
    tr.appendChild(act);
    body.appendChild(tr);
  }
  $("btn-reveal").disabled = !state.unlocked;
  $("btn-delete").disabled = !state.unlocked;
  showView("history");
}

async function reveal(name) {
  const data = await api("GET", "/api/secrets/" + name + "/value");
  const box = $("reveal-box");
  box.textContent = data.value;
  box.hidden = false;
  $("reveal-note").hidden = false;
}

function openForm(isEdit) {
  editing = isEdit;
  $("form-title").textContent = isEdit ? "edit " + currentSecret : "new secret";
  $("f-name").value = isEdit ? currentSecret : "";
  $("f-name").disabled = isEdit;
  $("f-value").value = "";
  $("f-tag").value = "";
  $("form-error").textContent = "";
  showView("form");
}

$("form-login").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  $("login-error").textContent = "";
  try {
    await api("POST", "/api/login", { token: $("login-token").value });
    await refreshSession();
  } catch (e) { $("login-error").textContent = e.message; }
});

$("form-unlock").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  $("unlock-error").textContent = "";
  try {
    const res = await api("POST", "/api/unlock", { password: $("unlock-password").value });
    $("modal-unlock").hidden = true;
    state.unlocked = true;
    state.verified = res.verified;
    await refreshSession();
  } catch (e) { $("unlock-error").textContent = e.message; }
});

$("btn-cancel-unlock").addEventListener("click", () => { $("modal-unlock").hidden = true; });
$("btn-unlock").addEventListener("click", () => openUnlock(!state.verified && state.authenticated ? "" : undefined));

$("btn-logout").addEventListener("click", async () => {
  try { await api("POST", "/api/logout"); } catch (_) {}
  state.authenticated = false;
  state.unlocked = false;
  showView("login");
});

$("btn-create").addEventListener("click", () => {
  if (!state.unlocked) { openUnlock("unlock required to create secrets"); return; }
  openForm(false);
});

$("btn-back").addEventListener("click", () => showView("list"));
$("btn-back2").addEventListener("click", () => showView(currentSecret ? "history" : "list"));

$("btn-reveal").addEventListener("click", async () => {
  try { await reveal(currentSecret); } catch (e) { alert(e.message); }
});

$("btn-edit").addEventListener("click", () => {
  if (!state.unlocked) { openUnlock("unlock required to edit"); return; }
  openForm(true);
});

$("btn-delete").addEventListener("click", async () => {
  if (!confirm("delete " + currentSecret + "?")) return;
  try {
    await api("DELETE", "/api/secrets/" + currentSecret);
    currentSecret = null;
    await loadList();
    showView("list");
  } catch (e) { alert(e.message); }
});

$("form-secret").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  $("form-error").textContent = "";
  const name = $("f-name").value.trim();
  const body = {};
  const value = $("f-value").value;
  const tag = $("f-tag").value.trim();
  if (value !== "") body.value = value;
  if (tag !== "" || editing) body.tag = tag;
  try {
    await api("POST", "/api/secrets/" + name, body);
    await loadList();
    showView("list");
  } catch (e) { $("form-error").textContent = e.message; }
});

setInterval(renderUnlockState, 30000);
refreshSession().catch(() => showView("login"));
