// MDANetPro browser node + client logic (port of android/core Engine.kt).
// The browser cannot open sockets, so it connects to a gateway node over WebSocket and is, to the
// network, a member behind NAT that uses the gateway as its relay. Keys stay in the browser and
// messages are onion-encrypted end to end; the gateway only forwards ciphertext.
import { Num, parse, dumps, bytes, copy, num, str, isObj } from "./canon.js";
import * as C from "./mcrypto.js";

const PORT = 50404;
const isVirtual = (ep) => /\.mda:\d+$/.test(String(ep || ""));
const normalize = (ep) => String(ep || "").trim();
const now = () => Date.now();
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const uid = () => C.randomHex(16);

export class Engine {
  constructor(storage) {
    this.storage = storage; // { load(): obj|null, save(obj), loadKeys(): identity|null, saveKeys(identity) }
    this.listeners = new Set();
    this.logs = [];
    this.pendingJoins = new Map();
    this.pendingUpdates = new Map();
    this.records = new Map(); // node address -> verified route record
    this.outgoing = [];
    this.unread = {};
    this.lastRoute = {};
    this.ws = null;
    this.wsState = "disconnected";
    this.wsWaiters = new Map();
    this.gatewayId = "";
    this.gatewayRecord = null;
    this.localRecord = null;
    this.seenNonces = new Map();
    this.circuits = new Map();
    this.senderCounter = 0;
    this.notices = [];
    this.timers = [];
  }

  // ------------------------------------------------------------------ setup & persistence
  async init() {
    this.identity = await this.storage.loadKeys();
    if (!this.identity) {
      this.identity = await C.generateIdentity();
      await this.storage.saveKeys(this.identity);
    }
    this.nodeId = `${await C.fingerprint(this.identity.publicPem)}.mda:${PORT}`;
    const s = this.storage.load() || {};
    this.name = s.name || "";
    this.setupDone = !!s.setup_done;
    this.gatewayUrl = s.gateway_url || "";
    this.coverTraffic = !!s.cover_traffic;
    this.activeNetwork = s.active_network || "";
    this.networks = isObj(s.networks) ? s.networks : {};
    this.contacts = Array.isArray(s.contacts) ? s.contacts : [];
    this.chats = isObj(s.chats) ? s.chats : {};
    for (const info of Object.values(this.networks)) await this.learnRecordsFrom(info.nodes);
    this.timers.push(setInterval(() => this.trafficTick().catch(() => {}), 4000));
    this.timers.push(setInterval(() => this.publish(), 2000));
    return this;
  }

  save() {
    this.storage.save(parse(dumps({
      name: this.name, setup_done: this.setupDone, gateway_url: this.gatewayUrl, cover_traffic: this.coverTraffic,
      active_network: this.activeNetwork, networks: this.networks, contacts: this.contacts,
      chats: Object.fromEntries(Object.entries(this.chats).map(([k, v]) => [k, v.slice(-500)])),
    })));
  }

  log(text) {
    const t = new Date().toTimeString().slice(0, 8);
    this.logs.push(`${t} ${text}`);
    if (this.logs.length > 300) this.logs.shift();
    this.publish();
  }

  notice(title, text) { this.notices.push({ title, text, id: uid() }); this.publish(); }

  subscribe(fn) { this.listeners.add(fn); fn(this.snapshot()); return () => this.listeners.delete(fn); }

  publish() { const s = this.snapshot(); for (const fn of this.listeners) { try { fn(s); } catch (e) { console.error(e); } } }

  snapshot() {
    const local = this.nodeId;
    const networks = Object.entries(this.networks).map(([name, info]) => ({
      name, type: str(info.type, "private"), myRole: str(info.my_role, "member"), status: str(info.membership_status, "active"),
      members: Object.entries(info.nodes || {}).map(([k, v]) => {
        const ep = this.endpointOf(v);
        return { nickname: this.nicknameOf(k, v) || ep, endpoint: ep, role: this.roleOf(k, v), isMe: ep === local };
      }),
    }));
    return {
      connected: this.wsState === "connected", wsState: this.wsState, nodeId: this.nodeId, name: this.name,
      setupDone: this.setupDone, gatewayUrl: this.gatewayUrl, gatewayId: this.gatewayId, coverTraffic: this.coverTraffic,
      activeNetwork: this.activeNetwork, networks,
      contacts: this.contacts.map((c) => ({ ...c, unread: this.unread[c.endpoint] || 0, lastText: (this.chats[c.endpoint] || []).slice(-1)[0]?.text || "" })),
      chats: this.chats,
      pending: [...this.pendingJoins.entries()].map(([id, p]) => ({ id, network: str(p.network), nickname: str(p.node_name, "New node"), endpoint: str(p.sender) })),
      notices: this.notices, logs: this.logs.slice(),
    };
  }

  // ------------------------------------------------------------------ gateway connection
  connect(url) {
    if (url) { this.gatewayUrl = url.trim(); this.save(); }
    if (!this.gatewayUrl) return;
    this.wantConnected = true;
    this.openSocket();
  }

  disconnect() {
    this.wantConnected = false;
    try { this.ws?.close(); } catch {}
  }

  openSocket() {
    try { this.ws?.close(); } catch {}
    let ws;
    try { ws = new WebSocket(this.gatewayUrl); } catch (e) { this.wsState = "error"; this.log(`Cannot open ${this.gatewayUrl}: ${e.message}`); return; }
    this.ws = ws;
    this.wsState = "connecting"; this.publish();
    ws.onopen = () => this.register().catch((e) => this.log(`Gateway registration failed: ${e.message}`));
    ws.onmessage = (e) => this.onWsMessage(typeof e.data === "string" ? e.data : "");
    ws.onclose = () => {
      if (this.ws !== ws) return;
      this.wsState = "disconnected"; this.publish();
      clearInterval(this.pingTimer);
      for (const [, w] of this.wsWaiters) w.reject(new Error("gateway disconnected"));
      this.wsWaiters.clear();
      if (this.wantConnected) setTimeout(() => { if (this.wantConnected && this.ws === ws) this.openSocket(); }, 3000);
    };
    ws.onerror = () => { if (this.wsState === "connecting") this.log(`Could not connect to ${this.gatewayUrl}.`); };
  }

  wsSend(obj) { this.ws?.send(dumps(obj)); }

  async register() {
    await this.refreshRecord();
    this.wsSend({ type: "relay_register", record: this.localRecord });
  }

  /** Our signed route record: reachable through the gateway (and its direct addresses). */
  async refreshRecord() {
    const via = (this.gatewayRecord?.routes || []).filter((r) => str(r.t) === "tcp").sort((a, b) => (str(a.s) === "public" ? -1 : 0) - (str(b.s) === "public" ? -1 : 0)).map((r) => str(r.a)).slice(0, 3);
    const routes = this.gatewayId ? [{ t: "relay", a: this.gatewayId, via }] : [];
    const record = { node: this.nodeId, pubkey: this.identity.publicPem, routes, pub_ip: "", nat: "symmetric", time: Num.seconds(), reachable: false };
    record.sig = await C.sign(this.identity, bytes(record));
    const changed = !this.localRecord || dumps(this.localRecord.routes) !== dumps(routes);
    this.localRecord = record;
    return changed;
  }

  onWsMessage(text) {
    let msg;
    try { msg = parse(text); } catch { return; }
    const type = str(msg.type);
    if (type === "relay_registered") {
      if (msg.ok !== true) { this.wsState = "error"; this.log(`Gateway refused: ${str(msg.error)}`); this.publish(); return; }
      const wasConnected = this.wsState === "connected";
      this.gatewayId = str(msg.gateway);
      this.gatewayRecord = isObj(msg.gateway_record) ? msg.gateway_record : null;
      this.wsState = "connected";
      clearInterval(this.pingTimer);
      this.pingTimer = setInterval(() => { try { this.wsSend({ type: "relay_ping" }); } catch {} }, 20000);
      this.refreshRecord().then(async (changed) => {
        if (changed) this.wsSend({ type: "relay_register", record: this.localRecord }); // now with the gateway route
        if (!wasConnected) { this.log(`Connected to gateway ${this.gatewayId}.`); this.upsertLocalNode(); this.broadcastRoutes(); }
      });
      this.publish();
    } else if (type === "relay_deliver") {
      const rid = msg.rid;
      this.processPacket(isObj(msg.packet) ? msg.packet : {}).then((reply) => this.wsSend({ type: "relay_reply", rid, reply }))
        .catch((e) => this.wsSend({ type: "relay_reply", rid, reply: { status: "error", error: e.message } }));
    } else if (type === "gateway_result") {
      const w = this.wsWaiters.get(str(msg.rid));
      if (w) { this.wsWaiters.delete(str(msg.rid)); w.resolve(msg); }
    }
  }

  /** Ask the gateway to deliver a packet (it routes: direct, hole punch or relay). */
  async send(to, packet, timeoutMs = 6000) {
    if (this.wsState !== "connected") throw new Error("not connected to a gateway");
    to = normalize(to);
    if (to === this.nodeId) return this.processPacket(copy(packet));
    const rid = uid();
    const records = [];
    const rec = this.recordFor(to);
    if (rec) records.push(rec);
    const result = await new Promise((resolve, reject) => {
      this.wsWaiters.set(rid, { resolve, reject });
      setTimeout(() => { if (this.wsWaiters.delete(rid)) reject(new Error("gateway timeout")); }, timeoutMs + 4000);
      this.wsSend({ type: "gateway_send", rid, to, packet, records, timeout: Math.round(timeoutMs / 1000) });
    });
    if (result.ok !== true) throw new Error(str(result.error, "send failed"));
    this.lastRoute[to] = str(result.route);
    return result.reply;
  }

  async gatewayInfo() {
    const rid = uid();
    const result = await new Promise((resolve, reject) => {
      this.wsWaiters.set(rid, { resolve, reject });
      setTimeout(() => { if (this.wsWaiters.delete(rid)) reject(new Error("gateway timeout")); }, 8000);
      this.wsSend({ type: "gateway_info", rid });
    });
    return result.reply;
  }

  // ------------------------------------------------------------------ incoming packets
  async processPacket(packet) {
    const target = str(packet._to);
    delete packet._to;
    if (target && target !== this.nodeId) return { status: "wrong_node", nodeid: this.nodeId };
    const type = str(packet.type);
    if (type === "ping") return { type: "pong", nodeid: this.nodeId, seen_ip: "" };
    if (type === "reach_probe") return this.answerReachProbe(packet);
    if (type === "hello") {
      if (isObj(packet.record)) await this.learnRecord(packet.record);
      return { type: "hello_reply", nodeid: this.nodeId, seen_ip: "", networks: await this.helloNetworks(), record: this.localRecord };
    }
    if (type === "punch_request") return { status: "punching" };
    if (type === "relay_forward") return { type: "relay_result", ok: false, error: "a browser cannot relay" };
    if (packet.routing === "onion" && (type === "real" || type === "fake")) return this.handleOnion(packet);
    await this.handlePacket(packet);
    return { status: "ok", nodeid: this.nodeId };
  }

  async answerReachProbe(packet) {
    const result = { type: "reach_result", nodeid: this.nodeId, seen_ip: "", callback_ok: false, callback_error: "" };
    const cb = str(packet.callback_node);
    if (!isVirtual(cb)) { result.callback_error = "cannot call back a plain address from a browser"; return result; }
    if (isObj(packet.record)) await this.learnRecord(packet.record);
    try {
      const reply = await this.send(cb, { type: "ping", nodeid: this.nodeId }, 8000);
      result.callback_ok = str(reply?.type) === "pong";
      result.callback_route = `via gateway: ${this.lastRoute[cb] || "?"}`;
    } catch (e) { result.callback_error = e.message; }
    return result;
  }

  // ------------------------------------------------------------------ onion messages
  async encryptLayer(layer, publicPem) {
    const hopKey = C.randomBytes(32);
    const sealed = await C.aesGcmEncrypt(hopKey, bytes(layer));
    return { scheme: "rsa-aes-gcm", ek: C.b64(await C.oaepEncrypt(publicPem, hopKey)), nonce: C.b64(sealed.nonce), tag: C.b64(sealed.tag), ct: C.b64(sealed.ct) };
  }

  async decryptLayer(layer) {
    const hopKey = await C.oaepDecrypt(this.identity, C.unb64(layer.ek));
    return parse(C.fromUtf8(await C.aesGcmDecrypt(hopKey, C.unb64(layer.nonce), C.unb64(layer.ct), C.unb64(layer.tag))));
  }

  packBody(text, size = 768) {
    let body = C.utf8(text);
    if (body.length > size) body = body.slice(0, size);
    const padded = new Uint8Array(size); padded.set(body); padded.set(C.randomBytes(size - body.length), body.length);
    return { body_b64: C.b64(padded), body_len: body.length };
  }

  async handleOnion(packet) {
    const routeId = str(packet.route_id);
    const nonce = str(packet.msg_nonce).trim();
    if (nonce) {
      for (const [k, t] of this.seenNonces) if (now() - t > 600000) this.seenNonces.delete(k);
      if (this.seenNonces.has(nonce)) return { status: "replay_dropped", nodeid: this.nodeId, route_id: routeId };
      this.seenNonces.set(nonce, now());
    }
    let layer;
    try { layer = await this.decryptLayer(packet.onion); } catch (e) { return { status: "decrypt_error", nodeid: this.nodeId, route_id: routeId, error: String(e.message) }; }
    const next = str(layer.next_hop);
    if (next) {
      const forward = { type: packet.type, routing: "onion", network: str(packet.network), route_id: routeId, circuit_id: str(packet.circuit_id),
        msg_nonce: nonce, sender_counter: packet.sender_counter ?? 0, sender: str(packet.sender), receiver: str(packet.receiver), onion: layer.inner, time: Num.seconds() };
      try { await this.send(next, forward, 5000); return { status: "forwarded", nodeid: this.nodeId, route_id: routeId }; }
      catch (e) { return { status: "forward_error", nodeid: this.nodeId, route_id: routeId, error: e.message }; }
    }
    if (packet.type === "fake") return { status: "fake_discarded", nodeid: this.nodeId, route_id: routeId };
    const pb = layer.payload?.packed_body || {};
    const raw = C.unb64(pb.body_b64 || "");
    const text = C.fromUtf8(raw.slice(0, Math.min(num(pb.body_len), raw.length)));
    await this.handlePacket({ type: "real", sender: str(packet.sender), network: str(packet.network), text });
    return { status: "delivered", nodeid: this.nodeId, route_id: routeId };
  }

  async sendOnion(receiver, text, network, type) {
    const keys = this.publicKeyMap(network);
    const recvKey = keys[receiver];
    if (!recvKey) throw new Error(`Missing receiver public key for ${receiver}`);
    const pool = this.networkEndpoints(network).filter((e) => e !== this.nodeId && e !== receiver && keys[e]);
    const cacheKey = `${network}|${receiver}|${type}`;
    let c = this.circuits.get(cacheKey);
    if (!c || now() > c.expires || c.uses >= 8 || !c.relays.every((r) => pool.includes(r))) {
      c = { id: `circuit-${uid()}`, relays: pool.sort(() => Math.random() - 0.5).slice(0, 2), expires: now() + 120000, uses: 0 };
      this.circuits.set(cacheKey, c);
    }
    c.uses++;
    const route = [...c.relays, receiver];
    const routeId = crypto.randomUUID();
    let onion = await this.encryptLayer({ next_hop: "", payload: { route_id: routeId, message_type: type, packed_body: this.packBody(text) } }, recvKey);
    for (let i = route.length - 2; i >= 0; i--) onion = await this.encryptLayer({ next_hop: route[i + 1], inner: onion }, keys[route[i]]);
    this.senderCounter++;
    const packet = { type, routing: "onion", network, route_id: routeId, circuit_id: c.id, msg_nonce: uid(), sender_counter: this.senderCounter,
      sender: this.nodeId, receiver, onion, time: Num.seconds() };
    return this.send(route[0], packet, 5000);
  }

  // ------------------------------------------------------------------ node entries
  endpointOf(entry) {
    if (typeof entry === "string") return normalize(entry);
    if (isObj(entry)) return normalize(str(entry.endpoint)) || (entry.host && entry.port ? `${str(entry.host)}:${str(entry.port)}` : "");
    return "";
  }
  roleOf(key, entry) { return isObj(entry) ? str(entry.role).trim().toLowerCase() : (key.toLowerCase().startsWith("seed") ? "seed" : ""); }
  nicknameOf(key, entry) {
    const n = isObj(entry) ? str(entry.nickname).trim() : "";
    if (n) return n;
    return key.trim() && key.trim().toLowerCase() !== "self" ? key.trim() : "";
  }
  samePubkey(a, b) { const x = str(a).trim(); return !!x && x === str(b).trim(); }

  putNodeEntry(nodes, name, entryIn, previous) {
    const entry = isObj(entryIn) ? { ...entryIn } : { endpoint: this.endpointOf(entryIn) };
    const endpoint = this.endpointOf(entry);
    const pubkey = str(entry.pubkey).trim();
    let match = null;
    if (pubkey) match = Object.keys(nodes).find((k) => isObj(nodes[k]) && this.samePubkey(nodes[k].pubkey, pubkey)) ?? null;
    if (match === null && endpoint) match = Object.keys(nodes).find((k) => this.endpointOf(nodes[k]) === endpoint) ?? null;
    if (match !== null) {
      const old = this.endpointOf(nodes[match]);
      if (old && endpoint && old !== endpoint && previous) previous.push(old);
      nodes[match] = isObj(nodes[match]) ? Object.assign(nodes[match], entry) : entry;
      return match;
    }
    const base = name.trim() || endpoint || "node";
    let key = base, i = 2;
    while (key in nodes) key = `${base}-${i++}`;
    nodes[key] = entry;
    return key;
  }

  upsertLocalNode() {
    for (const info of Object.values(this.networks)) {
      info.nodes = info.nodes || {};
      const mine = Object.values(info.nodes).find((v) => isObj(v) && this.samePubkey(v.pubkey, this.identity.publicPem));
      const entry = { endpoint: this.nodeId, nickname: this.name, role: (mine && str(mine.role)) || str(info.my_role, "member"), pubkey: this.identity.publicPem };
      if (this.localRecord) entry.record = this.localRecord;
      this.putNodeEntry(info.nodes, this.name, entry);
    }
    this.save();
  }

  networkEndpoints(network) {
    const info = this.networks[network];
    if (!info) return [];
    return [...new Set(Object.entries(info.nodes || {}).map(([k, v]) => this.endpointOf(v)).filter(Boolean))].sort();
  }

  publicKeyMap(network) {
    const map = {};
    for (const v of Object.values(this.networks[network]?.nodes || {})) {
      const ep = this.endpointOf(v), pk = isObj(v) ? str(v.pubkey).trim() : "";
      if (ep && pk) map[ep] = pk;
    }
    map[this.nodeId] = this.identity.publicPem;
    return map;
  }

  nicknameFor(ep) {
    for (const info of Object.values(this.networks)) for (const [k, v] of Object.entries(info.nodes || {})) if (this.endpointOf(v) === ep) { const n = this.nicknameOf(k, v); if (n) return n; }
    return this.contacts.find((c) => c.endpoint === ep)?.nickname || "";
  }

  // ------------------------------------------------------------------ route records
  async verifyRecord(r) {
    if (!isObj(r)) return false;
    try {
      const fp = await C.fingerprint(str(r.pubkey));
      if (!str(r.node).startsWith(`${fp}.mda:`)) return false;
      if (Math.abs(now() / 1000 - num(r.time)) > 30 * 86400) return false;
      const body = { ...r }; delete body.sig;
      return await C.verify(str(r.pubkey), bytes(body), str(r.sig));
    } catch { return false; }
  }

  async learnRecord(r) {
    if (!(await this.verifyRecord(r))) return false;
    const id = str(r.node);
    if (id === this.nodeId) return false;
    const cur = this.records.get(id);
    if (cur && num(cur.time) >= num(r.time)) return false;
    this.records.set(id, r);
    return true;
  }

  async learnRecordsFrom(nodes) {
    for (const v of Object.values(nodes || {})) {
      if (isObj(v) && isObj(v.record) && (!str(v.pubkey) || this.samePubkey(v.record.pubkey, v.pubkey))) await this.learnRecord(v.record);
    }
  }

  recordFor(ep) {
    if (this.records.has(ep)) return this.records.get(ep);
    for (const info of Object.values(this.networks)) for (const v of Object.values(info.nodes || {})) if (isObj(v) && this.endpointOf(v) === ep && isObj(v.record)) return v.record;
    return null;
  }

  async broadcastRoutes() {
    if (!this.localRecord) return;
    const payload = { type: "control", routing: "direct", action: "routes_update", network: "", sender: this.nodeId, record: this.localRecord };
    const targets = new Set(Object.keys(this.networks).flatMap((n) => this.networkEndpoints(n)));
    targets.delete(this.nodeId);
    for (const t of targets) this.send(t, payload, 4000).catch(() => {});
  }

  async handleRoutesUpdate(packet) {
    const record = packet.record;
    if (!isObj(record) || !(await this.verifyRecord(record))) return;
    await this.learnRecord(record);
    let changed = false;
    for (const info of Object.values(this.networks)) for (const v of Object.values(info.nodes || {})) {
      if (isObj(v) && this.samePubkey(v.pubkey, record.pubkey)) { v.record = record; v.endpoint = str(record.node); changed = true; }
    }
    if (changed) this.save();
  }

  // ------------------------------------------------------------------ joining
  async helloNetworks() {
    return Object.entries(this.networks)
      .filter(([, i]) => ["seed", "trusted"].includes(str(i.my_role).toLowerCase()) && str(i.membership_status, "active") === "active" && i.discoverable !== false)
      .map(([name, i]) => ({ network: name, type: str(i.type, "private"), description: str(i.description), rules: i.rules || [], min_approvals: Math.max(1, num(i.min_approvals, 2)),
        endpoint: this.nodeId, role: str(i.my_role), nickname: this.name, pubkey: this.identity.publicPem, port: PORT, record: this.localRecord }));
  }

  createNetwork(name) {
    name = name.trim();
    if (!name) return;
    if (this.networks[name]) { this.notice("Create network", `You already have a network called '${name}'.`); return; }
    this.networks[name] = { type: "private", description: "", rules: [], nodes: {}, membership_status: "active", my_role: "seed", min_approvals: 1, discoverable: true };
    this.networks[name].nodes[this.name] = { endpoint: this.nodeId, role: "seed", nickname: this.name, pubkey: this.identity.publicPem, record: this.localRecord };
    this.activeNetwork = name;
    this.save(); this.log(`Network created: ${name}`);
  }

  deleteNetwork(name) {
    delete this.networks[name];
    this.contacts = this.contacts.filter((c) => c.network !== name);
    if (this.activeNetwork === name) this.activeNetwork = Object.keys(this.networks)[0] || "";
    this.save(); this.publish();
  }

  /** Networks offered by the gateway node itself, or by another address reached through it. */
  async findNetworks(address) {
    let reply;
    if (!address) reply = await this.gatewayInfo();
    else {
      const ep = /:\d+$/.test(address) ? address : `${address}:${PORT}`;
      reply = await this.send(ep, { type: "hello", nodeid: this.nodeId, record: this.localRecord }, 6000);
    }
    if (!reply || str(reply.type) !== "hello_reply") throw new Error("no MDANetPro node answered there");
    const record = isObj(reply.record) && (await this.verifyRecord(reply.record)) ? reply.record : null;
    if (record) await this.learnRecord(record);
    return (reply.networks || []).filter((n) => isObj(n) && str(n.network)).map((n) => (record && str(record.node) === str(n.endpoint) ? { ...n, record } : n));
  }

  async joinFromSummary(s) {
    const name = str(s.network).trim(), endpoint = str(s.endpoint).trim();
    if (!name || !endpoint) return;
    if (str(this.networks[name]?.membership_status) === "active") { this.notice("Join network", `You are already a member of '${name}'.`); return; }
    const owner = str(s.nickname, "owner");
    const entry = { endpoint, role: str(s.role, "seed"), nickname: owner, pubkey: str(s.pubkey) };
    if (isObj(s.record) && (await this.verifyRecord(s.record))) { entry.record = s.record; await this.learnRecord(s.record); }
    await this.joinNetwork(name, str(s.type, "private"), str(s.description), (s.rules || []).map(String), { [owner]: entry }, Math.max(1, num(s.min_approvals, 2)));
  }

  async importMdar(text) {
    let p;
    try { p = parse(C.fromUtf8(C.unb64(text.replace(/\s+/g, "")))); } catch { p = null; }
    if (!isObj(p) || !str(p.magic)) { this.notice("Invite file", "This is not a valid .mdar invite."); return; }
    const rules = Array.isArray(p.rules) ? p.rules.map(String) : String(p.rules || "").split(",").map((x) => x.trim()).filter(Boolean);
    await this.joinNetwork(str(p.name).trim(), str(p.type, "private").toLowerCase() === "public" ? "public" : "private", str(p.description), rules, isObj(p.nodes) ? p.nodes : {}, Math.max(1, num(p.min_approvals, 2)));
  }

  async joinNetwork(name, type, description, rules, nodesIn, minApprovals) {
    const nodes = copy(nodesIn);
    await this.learnRecordsFrom(nodes);
    const targets = [...new Set(Object.entries(nodes).filter(([k, v]) => ["seed", "trusted"].includes(this.roleOf(k, v))).map(([, v]) => this.endpointOf(v)).filter((e) => e && e !== this.nodeId))];
    const info = this.networks[name] || {};
    Object.assign(info, { type, description, rules, nodes, membership_status: "pending_approval", my_role: "member", min_approvals: minApprovals });
    if (info.discoverable === undefined) info.discoverable = true;
    this.networks[name] = info;
    this.putNodeEntry(nodes, this.name, { endpoint: this.nodeId, role: "member", nickname: this.name, pubkey: this.identity.publicPem, record: this.localRecord });
    this.activeNetwork = name;
    this.save();
    const payload = { type: "control", routing: "direct", action: "join_request", network: name, sender: this.nodeId, node_name: this.name, description: "",
      requested_role: "member", public_key: this.identity.publicPem, record: this.localRecord, time: Num.seconds() };
    let sent = 0;
    for (const t of targets) {
      try { await this.send(t, payload, 6000); sent++; this.log(`Join request sent to ${this.nicknameFor(t) || t} for '${name}'.`); }
      catch (e) { this.log(`Join request failed to ${t}: ${e.message}`); }
    }
    if (sent) this.notice("Join request sent", "You will be notified here when the network owner approves it.");
    else this.notice("Join network", "Could not reach the network owner. They must be online, and your gateway must be able to reach them.");
  }

  // ------------------------------------------------------------------ control messages
  async handlePacket(packet) {
    const type = str(packet.type);
    if (type === "control") return this.handleControl(packet);
    if (type === "real" || type === "chat") {
      const sender = str(packet.sender);
      if (!this.contacts.some((c) => c.endpoint === sender)) this.contacts.push({ nickname: this.nicknameFor(sender) || "Peer", endpoint: sender, network: str(packet.network) });
      (this.chats[sender] = this.chats[sender] || []).push({ in: true, text: str(packet.text), time: now() });
      this.unread[sender] = (this.unread[sender] || 0) + 1;
      this.onChat?.(this.nicknameFor(sender) || sender, str(packet.text), sender);
      this.save(); this.publish();
    }
  }

  async handleControl(packet) {
    const action = str(packet.action).trim().toLowerCase();
    const network = str(packet.network).trim();
    if (action === "join_request") return this.handleJoinRequest(packet, network);
    if (action === "routes_update") return this.handleRoutesUpdate(packet);
    if (action === "address_update") { if (isObj(packet.record)) await this.learnRecord(packet.record); return; }
    if (action === "join_approved" || action === "node_list_update") return this.handleSignedUpdate(packet, network, action, action === "join_approved");
    if (action === "join_rejected") { this.log(`Join request rejected for '${network}'.`); this.notice("Join request rejected", str(packet.reason, "Rejected by the network owner.")); }
  }

  async handleJoinRequest(packet, network) {
    const info = this.networks[network];
    if (!info || !["seed", "trusted"].includes(str(info.my_role).toLowerCase()) || !str(packet.sender)) return;
    if (isObj(packet.record) && this.samePubkey(packet.record.pubkey, packet.public_key)) await this.learnRecord(packet.record);
    for (const [id, p] of this.pendingJoins) if (str(p.network) === network && str(p.sender) === str(packet.sender)) this.pendingJoins.delete(id);
    const id = uid();
    this.pendingJoins.set(id, packet);
    this.log(`Join request from ${str(packet.node_name, "New node")} for '${network}'.`);
    this.onJoinRequest?.(str(packet.node_name, "New node"), network);
    this.publish();
  }

  async rejectJoin(id) {
    const p = this.pendingJoins.get(id); if (!p) return;
    this.pendingJoins.delete(id);
    this.sendReliable(str(p.sender), { type: "control", routing: "direct", action: "join_rejected", network: str(p.network), reason: "Join request rejected by trusted/seed node.", sender: this.nodeId, time: Num.seconds() }, "join rejection");
    this.publish();
  }

  async approveJoin(id) {
    const p = this.pendingJoins.get(id); if (!p) return;
    this.pendingJoins.delete(id);
    const network = str(p.network), info = this.networks[network];
    if (!info) return;
    const sender = str(p.sender), name = str(p.node_name, "New node") || "New node", pub = str(p.public_key).trim();
    const entry = { endpoint: sender, role: "member", nickname: name, pubkey: pub };
    if (isObj(p.record) && this.samePubkey(p.record.pubkey, pub) && (await this.verifyRecord(p.record))) entry.record = p.record;
    this.putNodeEntry(info.nodes, name, entry);
    this.upsertContact(sender, name, network);
    this.save();
    const body = this.updateBody(info);
    const updateId = `update-${uid()}`;
    const hash = await C.sha256Hex(bytes(body));
    const joinVote = await this.signVote("join_approved", network, updateId, hash);
    const listVote = await this.signVote("node_list_update", network, updateId, hash);
    this.registerVote(network, "node_list_update", updateId, hash, body, listVote);
    this.sendReliable(sender, { type: "control", routing: "direct", action: "join_approved", network, update_id: updateId, update_hash: hash, update_body: body,
      signer: joinVote.signer, signer_pubkey: joinVote.signer_pubkey, signature: joinVote.signature, sender: this.nodeId, time: Num.seconds() }, "join approval");
    this.broadcastVote(network, "node_list_update", updateId, hash, body, listVote);
    this.log(`Join request approved for ${name} on '${network}'.`);
    this.publish();
  }

  upsertContact(endpoint, nickname, network) {
    const c = this.contacts.find((x) => x.endpoint === endpoint);
    if (c) { if (nickname) c.nickname = nickname; if (network) c.network = network; }
    else this.contacts.push({ nickname: nickname || endpoint, endpoint, network: network || "" });
  }

  updateBody(info) {
    return { network_type: str(info.type, "private"), network_description: str(info.description), network_rules: copy(info.rules || []),
      nodes: copy(info.nodes || {}), min_approvals: Math.max(1, num(info.min_approvals, 2)) };
  }

  voteSignable(action, network, updateId, hash, signer) { return { action, network, update_id: updateId, update_hash: hash, signer }; }

  async signVote(action, network, updateId, hash) {
    return { signer: this.nodeId, signer_pubkey: this.identity.publicPem, signature: await C.sign(this.identity, bytes(this.voteSignable(action, network, updateId, hash, this.nodeId))) };
  }

  registerVote(network, action, updateId, hash, body, vote) {
    if (!this.pendingUpdates.has(network)) this.pendingUpdates.set(network, new Map());
    const bucket = this.pendingUpdates.get(network);
    const key = `${action}|${updateId}`;
    if (!bucket.has(key)) bucket.set(key, { hash, body, votes: {}, applied: false });
    const p = bucket.get(key);
    if (p.hash !== hash) return null;
    p.votes[str(vote.signer)] = vote;
    return p;
  }

  requiredApprovals(network, body) {
    const base = Math.max(1, num(this.networks[network]?.min_approvals ?? body.min_approvals, 2));
    const trusted = Object.entries(body.nodes || {}).filter(([k, v]) => ["trusted", "seed"].includes(this.roleOf(k, v))).length;
    return trusted <= 1 ? 1 : Math.min(base, trusted);
  }

  async handleSignedUpdate(packet, network, action, markActive) {
    const updateId = str(packet.update_id).trim(), hash = str(packet.update_hash).trim(), body = packet.update_body;
    if (!updateId || !hash || !isObj(body)) return this.log(`Ignored malformed update for '${network}'.`);
    if ((await C.sha256Hex(bytes(body))) !== hash) return this.log(`Ignored update with hash mismatch for '${network}'.`);
    const vote = { signer: str(packet.signer), signer_pubkey: str(packet.signer_pubkey), signature: str(packet.signature) };
    if (!(await C.verify(vote.signer_pubkey, bytes(this.voteSignable(action, network, updateId, hash, vote.signer)), vote.signature)))
      return this.log(`Ignored update with invalid signature for '${network}'.`);
    const known = this.publicKeyMap(network)[vote.signer];
    if (known && known.trim() !== vote.signer_pubkey.trim()) return this.log(`Ignored update with signer key mismatch for '${network}'.`);
    const rank = { member: 0, trusted: 1, seed: 2 };
    let signerRole = "";
    for (const [k, v] of Object.entries(body.nodes || {})) if (this.endpointOf(v) === vote.signer) { const r = this.roleOf(k, v); if ((rank[r] ?? -1) > (rank[signerRole] ?? -1)) signerRole = r; }
    if (!["trusted", "seed"].includes(signerRole)) return this.log(`Ignored update from non-trusted signer for '${network}'.`);
    const p = this.registerVote(network, action, updateId, hash, body, vote);
    if (!p) return this.log(`Ignored conflicting update for '${network}'.`);
    const myRole = str(this.networks[network]?.my_role, "member").toLowerCase();
    if (action === "node_list_update" && ["trusted", "seed"].includes(myRole) && !p.votes[this.nodeId]) {
      const mine = await this.signVote(action, network, updateId, hash);
      p.votes[this.nodeId] = mine;
      this.broadcastVote(network, action, updateId, hash, body, mine);
    }
    const required = action === "join_approved" ? 1 : this.requiredApprovals(network, body);
    if (p.applied) return;
    if (Object.keys(p.votes).length < required) return this.log(`Pending update for '${network}' (${Object.keys(p.votes).length}/${required} approvals).`);
    p.applied = true;
    await this.applyUpdate(body, network, markActive);
  }

  broadcastVote(network, action, updateId, hash, body, vote) {
    const payload = { type: "control", routing: "direct", action, network, update_id: updateId, update_hash: hash, update_body: body,
      signer: vote.signer, signer_pubkey: vote.signer_pubkey, signature: vote.signature, sender: this.nodeId, time: Num.seconds() };
    for (const ep of this.networkEndpoints(network)) if (ep !== this.nodeId) this.sendReliable(ep, payload, action);
  }

  async applyUpdate(body, network, markActive) {
    const info = this.networks[network] || { type: "private", description: "", rules: [], nodes: {}, my_role: "member", min_approvals: 2 };
    const t = str(body.network_type).toLowerCase();
    if (t === "private" || t === "public") info.type = t;
    info.description = str(body.network_description, info.description);
    if (Array.isArray(body.network_rules)) info.rules = body.network_rules.map((r) => str(r).trim()).filter(Boolean);
    info.min_approvals = Math.max(1, num(body.min_approvals, num(info.min_approvals, 2)));
    const wasPending = str(info.membership_status) === "pending_approval";
    const merged = copy(info.nodes || {});
    await this.learnRecordsFrom(body.nodes);
    for (const [k, v] of Object.entries(body.nodes || {})) this.putNodeEntry(merged, k, v);
    info.nodes = merged;
    for (const [k, v] of Object.entries(merged)) if (this.endpointOf(v) === this.nodeId) { const r = this.roleOf(k, v); if (["member", "trusted", "seed"].includes(r)) info.my_role = r; }
    if (markActive || !info.membership_status) info.membership_status = "active";
    this.networks[network] = info;
    if (markActive) this.activeNetwork = network;
    for (const [k, v] of Object.entries(merged)) {
      const ep = this.endpointOf(v);
      if (ep && ep !== this.nodeId) this.upsertContact(ep, this.nicknameOf(k, v) || "Peer", network);
    }
    this.save();
    this.log(`Network '${network}' synchronized.`);
    if (markActive && wasPending) {
      setTimeout(() => this.broadcastRoutes(), 500);
      this.notice("Joined", `You joined '${network}'. The members now appear in your contacts.`);
    }
    this.publish();
  }

  async sendReliable(endpoint, payloadIn, label, withinMs = 180000) {
    const payload = copy(payloadIn);
    const deadline = now() + withinMs;
    for (let attempt = 1; now() < deadline; attempt++) {
      try {
        await this.send(endpoint, payload, 6000);
        if (attempt > 1) this.log(`${label} delivered to ${this.nicknameFor(endpoint) || endpoint} (attempt ${attempt}).`);
        return;
      } catch { await sleep(Math.min(3000 * attempt, 15000)); }
    }
    this.log(`Could not deliver ${label} to ${endpoint}.`);
  }

  // ------------------------------------------------------------------ chat & traffic
  sendChat(endpoint, text) {
    if (!text.trim()) return;
    const c = this.contacts.find((x) => x.endpoint === endpoint);
    if (!c) return;
    if (str(this.networks[c.network]?.membership_status, "active") !== "active") { this.notice("Chat", `Wait until your membership in '${c.network}' is approved.`); return; }
    this.outgoing.push({ receiver: endpoint, text, network: c.network });
    (this.chats[endpoint] = this.chats[endpoint] || []).push({ in: false, text, time: now() });
    this.save(); this.publish();
    this.trafficTick().catch(() => {});
  }

  markRead(ep) { delete this.unread[ep]; this.publish(); }

  async trafficTick() {
    if (this.wsState !== "connected" || this.sending) return;
    this.sending = true;
    try {
      const item = this.outgoing.shift();
      if (item) {
        try { await this.sendOnion(item.receiver, item.text, item.network, "real"); }
        catch (e) { this.log(`Message to ${this.nicknameFor(item.receiver)} failed: ${e.message}`); }
        return;
      }
      if (!this.coverTraffic) return;
      const peers = this.contacts.filter((c) => c.network === this.activeNetwork).map((c) => c.endpoint);
      if (peers.length) await this.sendOnion(peers[Math.floor(Math.random() * peers.length)], `cover-${Math.floor(now() / 1000)}`, this.activeNetwork, "fake").catch(() => {});
    } finally { this.sending = false; }
  }

  async testConnection() {
    const lines = [{ ok: null, text: `Gateway: ${this.wsState === "connected" ? `connected (${this.gatewayUrl})` : "not connected"}` }];
    const network = this.activeNetwork;
    const rank = { seed: 0, trusted: 1 };
    const targets = Object.entries(this.networks[network]?.nodes || {}).map(([k, v]) => ({ name: this.nicknameOf(k, v), ep: this.endpointOf(v), role: this.roleOf(k, v) }))
      .filter((t) => t.ep && t.ep !== this.nodeId).sort((a, b) => (rank[a.role] ?? 2) - (rank[b.role] ?? 2)).slice(0, 6);
    if (!targets.length) lines.push({ ok: null, text: `There are no other members in '${network || "–"}' yet.` });
    for (const t of targets) {
      try {
        const r = await this.send(t.ep, { type: "reach_probe", nodeid: this.nodeId, callback_node: this.nodeId, callback_port: PORT, record: this.localRecord }, 8000);
        if (str(r?.type) === "reach_result" && r.callback_ok === true) lines.push({ ok: true, text: `${t.name} [${t.role}]: connected both ways.\n  you → them: ${this.lastRoute[t.ep] ? `via gateway, ${this.lastRoute[t.ep]}` : "it is your gateway"}\n  them → you: ${str(r.callback_route)}` });
        else lines.push({ ok: false, text: `${t.name}: you can reach it, but it can't reach you back (${str(r?.callback_error, "no answer")}).` });
      } catch (e) { lines.push({ ok: false, text: `${t.name}: can't reach it (${e.message}).` }); }
    }
    return lines;
  }

  // ------------------------------------------------------------------ settings
  setName(name) { this.name = name.trim().slice(0, 32); this.upsertLocalNode(); this.publish(); }
  completeSetup(name, url) { this.name = name.trim().slice(0, 32); this.setupDone = true; this.save(); this.connect(url); this.publish(); }
  setCoverTraffic(on) { this.coverTraffic = !!on; this.save(); this.publish(); }
  setActiveNetwork(n) { if (this.networks[n]) { this.activeNetwork = n; this.save(); this.publish(); } }
  dismissNotice(id) { this.notices = this.notices.filter((n) => n.id !== id); this.publish(); }

  exportMdar(network) {
    const info = this.networks[network];
    if (!info) return null;
    const nodes = {};
    for (const [k, v] of Object.entries(info.nodes || {})) {
      const ep = this.endpointOf(v); if (!ep) continue;
      const e = { endpoint: ep, role: this.roleOf(k, v) || "member", nickname: this.nicknameOf(k, v) || ep, pubkey: isObj(v) ? str(v.pubkey) : "" };
      const rec = this.recordFor(ep) || (ep === this.nodeId ? this.localRecord : null);
      if (rec) e.record = rec;
      let key = e.nickname, i = 2; while (key in nodes) key = `${e.nickname}-${i++}`;
      nodes[key] = e;
    }
    const payload = { magic: "**MDA Project Network profile**", name: network, type: str(info.type, "private"), description: str(info.description), rules: info.rules || [], nodes };
    return C.b64(C.utf8(dumps(payload)));
  }
}
