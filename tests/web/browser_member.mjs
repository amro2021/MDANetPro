// Drives the real web app in headless Chrome against the Python app (local + CI).
// usage: node browser_member.mjs http://localhost:8080/ SHOTDIR [chrome-path]
import puppeteer from "puppeteer-core";
import fs from "fs";
const [url = "http://localhost:8080/", shots = "shots", chrome = "/usr/bin/google-chrome"] = process.argv.slice(2);
fs.mkdirSync(shots, { recursive: true });
const browser = await puppeteer.launch({ executablePath: chrome, headless: true, args: ["--no-sandbox", "--window-size=420,860"] });
const page = await browser.newPage();
await page.setViewport({ width: 420, height: 860, deviceScaleFactor: 1 });
const errors = [];
page.on("pageerror", (e) => errors.push(e.message));
page.on("console", (m) => { if (m.type() === "error") errors.push(m.text()); });
let failed = 0;
const check = (label, ok) => { console.log(`${ok ? "PASS" : "FAIL"} ${label}`); if (!ok) failed++; return ok; };
const shot = (name) => page.screenshot({ path: `${shots}/${name}.png` });
const clickText = async (text, timeout = 30000) => {
  const el = await page.waitForSelector(`::-p-xpath(//*[self::button or self::b or self::div][normalize-space(text())=${JSON.stringify(text)}])`, { timeout });
  await el.click(); await new Promise((r) => setTimeout(r, 400));
};
const waitText = async (text, timeout) => { try { await page.waitForFunction((t) => document.body.innerText.includes(t), { timeout }, text); return true; } catch { return false; } };

await page.goto(url, { waitUntil: "networkidle0" });
await page.waitForSelector("#s-name");
await shot("01-setup");
await page.type("#s-name", "Browsy");
await clickText("Continue");
check("connected to the gateway (Python app)", await waitText("online", 20000));
await clickText("Networks");
await shot("02-networks");
await clickText("Join a network on this gateway");
await page.waitForSelector("dialog[open]");
await shot("03-choose");
await clickText("Ask to join");
// "Join request sent" may show first; dismiss it and wait for "You joined".
const joined = await page.waitForFunction(() => {
  if (document.body.innerText.includes("You joined")) return true;
  const d = document.querySelector("dialog[open]");
  if (d && d.innerText.includes("Join request sent")) d.querySelector("button")?.click();
  return false;
}, { timeout: 120000, polling: 500 }).then(() => true, () => false);
check("approved by the Python app ('You joined')", joined);
await shot("04-joined");
await clickText("OK");
await clickText("Chats");
check("chat from the PC arrived", await waitText("welcome Browsy", 90000));
await shot("05-chats");
await clickText("Amr");
await page.type("#msg", "thanks from Browsy");
await clickText("Send");
await new Promise((r) => setTimeout(r, 2500));
await shot("06-chat");
const engineLog = await page.evaluate(() => window.mdaEngine.logs.slice(-12).join("\n") + "\noutgoing=" + window.mdaEngine.outgoing.length + " sending=" + window.mdaEngine.sending);
console.log("ENGINE LOG:\n" + engineLog);
await page.click("[data-act=back]");
await clickText("Status");
await clickText("Test connection");
check("connection test: both ways", await waitText("connected both ways", 60000));
await shot("07-status");
await page.reload({ waitUntil: "networkidle0" });
check("after reload: still a member (keys + state persisted)", await waitText("Amr", 20000));
check("no JavaScript errors", errors.length === 0);
errors.forEach((e) => console.log("JS ERROR", e));
await new Promise((r) => setTimeout(r, 15000));
console.log("RESULT:", failed ? `${failed} FAILED` : "ALL PASSED");
await browser.close();
process.exit(failed ? 1 : 0);
