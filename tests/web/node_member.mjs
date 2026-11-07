// Runs the web app's engine in Node.js against the Python app's web gateway (CI + local test).
// usage: node node_member.mjs ws://127.0.0.1:50406 NAME NETWORK SEEDNICK
import { Engine } from "../../web/js/engine.js";
const [url = "ws://127.0.0.1:50406", name = "Webby", network = "Interop", seedNick = "Amr", joinAddress = ""] = process.argv.slice(2);
const store = { state: null, keys: null, load() { return this.state; }, save(s) { this.state = s; }, async loadKeys() { return this.keys; }, async saveKeys(k) { this.keys = k; } };
const engine = await new Engine(store).init();
let failed = 0;
const check = (label, ok) => { console.log(`${ok ? "PASS" : "FAIL"} ${label}`); if (!ok) failed++; return ok; };
const waitFor = async (label, cond, ms = 120000) => {
  const end = Date.now() + ms;
  while (Date.now() < end) { if (await cond()) return check(label, true); await new Promise((r) => setTimeout(r, 300)); }
  return check(label, false);
};
engine.completeSetup(name, url);
await waitFor("connected to the gateway", () => engine.wsState === "connected", 20000);
const nets = await engine.findNetworks(joinAddress);
check(`${joinAddress ? joinAddress : "gateway"} offers '${network}'`, nets.some((n) => n.network === network));
await engine.joinFromSummary(nets.find((n) => n.network === network));
await waitFor(`joined '${network}' (approved by the Python app)`, () => engine.networks[network]?.membership_status === "active");
await waitFor("seed in contacts", () => engine.contacts.some((c) => c.nickname === seedNick));
await waitFor(`received chat from ${seedNick}`, () => Object.values(engine.chats).flat().some((m) => m.in && m.text === `welcome ${name}`));
engine.sendChat(engine.contacts.find((c) => c.nickname === seedNick).endpoint, `thanks from ${name}`);
const lines = await engine.testConnection();
lines.forEach((l) => console.log("TEST", l.text.replace(/\n/g, " | ")));
check("connection test: connected both ways", lines.some((l) => l.ok === true));
await new Promise((r) => setTimeout(r, 20000));
engine.logs.slice(-15).forEach((l) => console.log("LOG", l));
console.log("RESULT:", failed ? `${failed} FAILED` : "ALL PASSED");
engine.disconnect();
process.exit(failed ? 1 : 0);
