// MDANetPro web app UI (plain DOM, no build step: works as static files on GitHub Pages).
import { Engine } from "./engine.js";
import { parse, dumps } from "./canon.js";

const $ = (sel) => document.querySelector(sel);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const time = (ms) => new Date(ms).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });

// ---- storage: state in localStorage, keys (non-extractable CryptoKeys) in IndexedDB ----------
const STATE_KEY = "mdanetpro_state";
function idb() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open("mdanetpro", 1);
    req.onupgradeneeded = () => req.result.createObjectStore("keys");
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}
const storage = {
  // Canonical JSON keeps numbers' exact text, so stored signed records still verify after a reload.
  load() { try { const t = localStorage.getItem(STATE_KEY); return t ? parse(t) : null; } catch { return null; } },
  save(state) { localStorage.setItem(STATE_KEY, dumps(state)); },
  async loadKeys() {
    const db = await idb();
    return new Promise((resolve) => { const r = db.transaction("keys").objectStore("keys").get("identity"); r.onsuccess = () => resolve(r.result || null); r.onerror = () => resolve(null); });
  },
  async saveKeys(identity) {
    const db = await idb();
    return new Promise((resolve, reject) => { const tx = db.transaction("keys", "readwrite"); tx.objectStore("keys").put(identity, "identity"); tx.oncomplete = resolve; tx.onerror = () => reject(tx.error); });
  },
};

// ---- default gateway: ?gateway=… in the link, else this computer's PC app -----------------------
const params = new URLSearchParams(location.search);
const defaultGateway = params.get("gateway") || "ws://localhost:50406";

const ui = { tab: "chats", chat: null, network: null, lastHtml: new Map(), tests: null, testing: false };
let engine, snap;

function setHTML(el, html) {
  if (ui.lastHtml.get(el) === html) return;
  ui.lastHtml.set(el, html);
  el.innerHTML = html;
}

// ---- dialogs -------------------------------------------------------------------------------
const dialog = $("#dialog");
function openDialog(html, onSubmit) {
  dialog.innerHTML = `<form method="dialog">${html}</form>`;
  dialog.querySelector("form").onsubmit = (e) => {
    const action = e.submitter?.value;
    if (action === "ok" && onSubmit) { if (onSubmit(new FormData(e.target)) === false) e.preventDefault(); }
  };
  dialog.showModal();
}
// Notices wait their turn: one arriving while a dialog is open is shown when it closes.
const noticeQueue = [];
function showNextNotice() {
  if (dialog.open || !noticeQueue.length) return;
  const n = noticeQueue.shift();
  notice(n.title, n.text);
}
dialog.addEventListener("close", () => setTimeout(showNextNotice, 50));
function notice(title, text) {
  openDialog(`<h3>${esc(title)}</h3><p>${esc(text)}</p><div class="row" style="justify-content:flex-end"><button class="btn" value="close">OK</button></div>`);
}

// ---- screens -------------------------------------------------------------------------------
function render() {
  if (!snap) return;
  const conn = $("#conn");
  conn.textContent = snap.connected ? "online" : snap.wsState === "connecting" ? "connecting…" : "offline";
  conn.className = "pill " + (snap.connected ? "on" : "off");
  for (const n of snap.notices) { engine.dismissNotice(n.id); noticeQueue.push(n); }
  showNextNotice();
  if (!snap.setupDone) { $("#tabs").hidden = true; return renderSetup(); }
  $("#tabs").hidden = !!ui.chat;
  for (const b of document.querySelectorAll("#tabs button")) b.classList.toggle("active", b.dataset.tab === ui.tab);
  const unread = snap.contacts.reduce((a, c) => a + c.unread, 0);
  $("#unread").hidden = !unread; $("#unread").textContent = unread;
  if (ui.chat) return renderChat();
  const main = $("#main");
  const html = requestsHtml() + (ui.tab === "chats" ? chatsHtml() : ui.tab === "networks" ? (ui.network ? networkHtml() : networksHtml()) : statusHtml());
  setHTML(main, html);
}

function renderSetup() {
  const main = $("#main");
  if (main.dataset.screen === "setup") return;
  main.dataset.screen = "setup";
  ui.lastHtml.delete(main);
  main.innerHTML = `<div class="section">
    <h1>Welcome to MDANetPro</h1>
    <p>Chat with the members of your private networks from this browser. Your keys are created and kept on this device.</p>
    <label>Your name</label><input id="s-name" placeholder="The name others will see" autocomplete="name">
    <label>Gateway</label><input id="s-gw" value="${esc(defaultGateway)}">
    <p class="muted">Browsers connect through a gateway: the MDANetPro app on your PC (<code>ws://localhost:50406</code>), or a server
      (<code>wss://…</code>) you were given. The gateway only forwards encrypted messages.</p>
    <button class="btn wide" id="s-go">Continue</button></div>`;
  $("#s-go").onclick = () => {
    const name = $("#s-name").value.trim();
    if (!name) return $("#s-name").focus();
    main.dataset.screen = "";
    engine.completeSetup(name, $("#s-gw").value.trim());
  };
}

function requestsHtml() {
  return snap.pending.map((r) => `<div class="card warn" style="margin:10px 16px">
    <b>${esc(r.nickname)}</b> wants to join <b>${esc(r.network)}</b>
    <div class="row" style="margin-top:8px"><button class="btn" data-act="approve" data-id="${esc(r.id)}">Approve</button>
    <button class="btn outline" data-act="reject" data-id="${esc(r.id)}">Reject</button></div></div>`).join("");
}

function chatsHtml() {
  if (!snap.contacts.length) return `<div class="section"><b>No contacts yet.</b><p class="muted">Join or create a network in the Networks tab. Members appear here once you are approved.</p></div>`;
  const groups = {};
  for (const c of snap.contacts) (groups[c.network || "Other"] = groups[c.network || "Other"] || []).push(c);
  return Object.entries(groups).map(([net, cs]) => `<h2 style="padding:0 16px">${esc(net)}</h2>` + cs.map((c) => `
    <div class="contact" data-act="chat" data-ep="${esc(c.endpoint)}"><div class="avatar">${esc((c.nickname || "?")[0].toUpperCase())}</div>
    <div class="grow"><b>${esc(c.nickname)}</b><div class="muted ellipsis">${esc(c.lastText || "Tap to chat")}</div></div>
    ${c.unread ? `<span class="badge" style="position:static">${c.unread}</span>` : ""}</div>`).join("")).join("");
}

function renderChat() {
  const main = $("#main");
  const c = snap.contacts.find((x) => x.endpoint === ui.chat);
  $("#title").innerHTML = `<button class="back" data-act="back">←</button>${esc(c?.nickname || "Chat")} <span class="muted" style="color:#cfe0f2">${esc(c?.network || "")}</span>`;
  if (main.dataset.screen !== "chat:" + ui.chat) {
    main.dataset.screen = "chat:" + ui.chat;
    ui.lastHtml.delete(main);
    main.innerHTML = `<div class="chatlog" id="log"></div><div class="composer"><input id="msg" placeholder="Message" autocomplete="off"><button class="btn" id="send">Send</button></div>`;
    const send = () => { const t = $("#msg").value; if (t.trim()) { engine.sendChat(ui.chat, t); $("#msg").value = ""; } };
    $("#send").onclick = send;
    $("#msg").onkeydown = (e) => { if (e.key === "Enter") send(); };
    $("#msg").focus();
  }
  const msgs = snap.chats[ui.chat] || [];
  const log = $("#log");
  const before = log.innerHTML.length;
  setHTML(log, msgs.map((m) => `<div class="bubble ${m.in ? "in" : "out"}">${esc(m.text)}<span class="t">${time(m.time)}</span></div>`).join(""));
  if (log.innerHTML.length !== before) main.scrollTop = main.scrollHeight;
  if (c?.unread) engine.markRead(ui.chat);
}

function networksHtml() {
  const nets = snap.networks.map((n) => `<div class="card click" data-act="net" data-name="${esc(n.name)}">
    <b>${esc(n.name)}</b>${n.name === snap.activeNetwork ? ' <span class="muted">(active)</span>' : ""}
    <div class="muted">${n.members.length} member(s) · you: ${esc(n.myRole)} · ${n.status === "active" ? "joined" : "waiting for approval"}</div></div>`).join("");
  return `<div class="section"><h2>Your networks</h2>${nets || '<p class="muted">None yet.</p>'}
    <button class="btn wide" data-act="find">Join a network on this gateway</button>
    <button class="btn wide outline" data-act="address">Join by address</button>
    <button class="btn wide outline" data-act="invite">Join with an invite (.mdar)</button>
    <button class="btn wide outline" data-act="create">Create a network</button>
    <p class="muted">A network you create here is only reachable while this page is open. For an always-on network, create it in the PC app.</p></div>`;
}

function networkHtml() {
  const n = snap.networks.find((x) => x.name === ui.network);
  if (!n) { ui.network = null; return networksHtml(); }
  return `<div class="section"><button class="btn outline" data-act="nets">← Networks</button>
    <h1>${esc(n.name)}</h1><p>Type: ${esc(n.type)} · You: ${esc(n.myRole)} · ${n.status === "active" ? "joined" : "waiting for approval"}</p>
    ${n.name !== snap.activeNetwork ? `<button class="btn outline" data-act="activate" data-name="${esc(n.name)}">Make active</button>` : ""}
    <h2>Members</h2>${n.members.map((m) => `<div>• ${esc(m.nickname)}${m.isMe ? " (you)" : ""} – ${esc(m.role)}</div>`).join("")}
    <h2>Invite</h2><div class="row"><button class="btn" data-act="download" data-name="${esc(n.name)}">Download .mdar</button>
    <button class="btn outline" data-act="copy" data-name="${esc(n.name)}">Copy invite</button></div>
    <h2></h2><button class="btn outline danger" data-act="delete" data-name="${esc(n.name)}">Delete network</button></div>`;
}

function statusHtml() {
  const tests = ui.tests ? `<div class="card">${ui.tests.map((l) => `<div>${l.ok === true ? "✅ " : l.ok === false ? "❌ " : ""}${esc(l.text).replace(/\n/g, "<br>")}</div>`).join("")}</div>` : "";
  return `<div class="section">
    <div class="card"><b class="${snap.connected ? "ok" : "bad"}">${snap.connected ? "Connected" : "Not connected"}</b>
      <div class="muted">Gateway: ${esc(snap.gatewayUrl || "–")}</div>
      <div class="muted">Your address: <code>${esc(snap.nodeId)}</code></div>
      <div class="muted">Active network: ${esc(snap.activeNetwork || "–")}</div></div>
    <button class="btn" data-act="test" ${snap.connected && !ui.testing ? "" : "disabled"}>${ui.testing ? "Testing…" : "Test connection"}</button>
    ${tests}
    <h2>Settings</h2>
    <label>Your name</label><input id="set-name" value="${esc(snap.name)}">
    <label>Gateway</label><input id="set-gw" value="${esc(snap.gatewayUrl)}">
    <label class="row"><input type="checkbox" id="set-cover" style="width:auto;margin:0" ${snap.coverTraffic ? "checked" : ""}> Cover traffic (hides when you really send; more data)</label>
    <div class="row" style="margin-top:10px"><button class="btn" data-act="save">Save</button></div>
    <h2>Log</h2><pre class="log">${esc(snap.logs.slice(-60).join("\n"))}</pre></div>`;
}

// ---- actions -------------------------------------------------------------------------------
function chooseNetworks(nets) {
  if (!nets.length) return notice("No networks", "That node is reachable, but it has no networks open for joining.");
  openDialog(`<h3>Choose a network</h3>${nets.map((n, i) => `<label class="row card" style="margin:6px 0"><input type="radio" name="n" value="${i}" style="width:auto;margin:0" ${i ? "" : "checked"}>
    <span><b>${esc(n.network)}</b><br><span class="muted">owner: ${esc(n.nickname)}</span></span></label>`).join("")}
    <div class="row" style="justify-content:flex-end"><button class="btn outline" value="cancel">Cancel</button><button class="btn" value="ok">Ask to join</button></div>`,
    (form) => { engine.joinFromSummary(nets[Number(form.get("n"))]); });
}

async function act(el) {
  const a = el.dataset.act;
  try {
    if (a === "approve") engine.approveJoin(el.dataset.id);
    else if (a === "reject") engine.rejectJoin(el.dataset.id);
    else if (a === "chat") { ui.chat = el.dataset.ep; render(); }
    else if (a === "back") { ui.chat = null; $("#title").textContent = "MDANetPro"; $("#main").dataset.screen = ""; ui.lastHtml.delete($("#main")); render(); }
    else if (a === "net") { ui.network = el.dataset.name; render(); }
    else if (a === "nets") { ui.network = null; render(); }
    else if (a === "activate") engine.setActiveNetwork(el.dataset.name);
    else if (a === "find") chooseNetworks(await engine.findNetworks(""));
    else if (a === "address") openDialog(`<h3>Join by address</h3><p class="muted">The network owner's address: their public IP for the internet, or local IP on the same network.</p>
        <input name="addr" placeholder="e.g. 85.10.20.30" required><div class="row" style="justify-content:flex-end"><button class="btn outline" value="cancel" formnovalidate>Cancel</button><button class="btn" value="ok">Find networks</button></div>`,
        (form) => { engine.findNetworks(String(form.get("addr")).trim()).then(chooseNetworks).catch((e) => notice("Join by address", e.message)); });
    else if (a === "invite") openDialog(`<h3>Join with an invite</h3><input type="file" name="file" accept=".mdar,*/*"><p class="muted">or paste the invite text:</p><textarea name="text"></textarea>
        <div class="row" style="justify-content:flex-end"><button class="btn outline" value="cancel">Cancel</button><button class="btn" value="ok">Join</button></div>`,
        (form) => { const f = form.get("file"); if (f && f.size) f.text().then((t) => engine.importMdar(t)); else if (String(form.get("text")).trim()) engine.importMdar(String(form.get("text"))); });
    else if (a === "create") openDialog(`<h3>Create a network</h3><input name="name" placeholder="Network name" required><p class="muted">You are the owner and approve everyone who asks to join.</p>
        <div class="row" style="justify-content:flex-end"><button class="btn outline" value="cancel" formnovalidate>Cancel</button><button class="btn" value="ok">Create</button></div>`,
        (form) => engine.createNetwork(String(form.get("name"))));
    else if (a === "download") {
      const blob = new Blob([engine.exportMdar(el.dataset.name)], { type: "application/octet-stream" });
      const link = Object.assign(document.createElement("a"), { href: URL.createObjectURL(blob), download: `${el.dataset.name.replace(/[^\w-]/g, "_")}.mdar` });
      link.click();
    } else if (a === "copy") { await navigator.clipboard.writeText(engine.exportMdar(el.dataset.name)); notice("Invite copied", "Paste it to the person you want to invite."); }
    else if (a === "delete") { if (confirm(`Delete '${el.dataset.name}' from this browser?`)) { engine.deleteNetwork(el.dataset.name); ui.network = null; } }
    else if (a === "test") { ui.testing = true; ui.tests = null; render(); ui.tests = await engine.testConnection(); ui.testing = false; render(); }
    else if (a === "save") {
      engine.setName($("#set-name").value); engine.setCoverTraffic($("#set-cover").checked);
      const gw = $("#set-gw").value.trim();
      if (gw && gw !== snap.gatewayUrl) engine.connect(gw);
    }
  } catch (e) { notice("Something went wrong", e.message); }
}

document.addEventListener("click", (e) => {
  const el = e.target.closest("[data-act]");
  if (el) { e.preventDefault(); act(el); }
  const tab = e.target.closest("#tabs button");
  if (tab) { ui.tab = tab.dataset.tab; ui.network = null; render(); }
});

// ---- start ---------------------------------------------------------------------------------
engine = await new Engine(storage).init();
engine.onChat = (from, text) => {
  if (document.hidden && "Notification" in window && Notification.permission === "granted") new Notification(from, { body: text, icon: "icon.svg" });
};
engine.onJoinRequest = (name, network) => {
  if (document.hidden && "Notification" in window && Notification.permission === "granted") new Notification("Join request", { body: `${name} wants to join ${network}`, icon: "icon.svg" });
};
if ("Notification" in window && Notification.permission === "default") document.addEventListener("click", () => Notification.requestPermission(), { once: true });
engine.subscribe((s) => { snap = s; render(); });
if (engine.setupDone) engine.connect();
window.mdaEngine = engine; // handy for debugging and the automated browser test
