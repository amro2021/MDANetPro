// JSON byte-compatible with Python's json.dumps(obj, sort_keys=True, separators=(",", ":")).
// Signatures and update hashes are computed over that exact text, so numbers keep their
// original lexeme (Num.raw) and strings are escaped exactly like Python (ensure_ascii).

export class Num {
  constructor(raw) { this.raw = String(raw); }
  valueOf() { return Number(this.raw); }
  toString() { return this.raw; }
  toJSON() { return Number(this.raw); }
  // Seconds as Python's time.time() prints them: "1794043339.512", "1794043339.0".
  static seconds(ms = Date.now()) {
    const whole = Math.floor(ms / 1000);
    let frac = String(ms % 1000).padStart(3, "0").replace(/0+$/, "");
    return new Num(`${whole}.${frac || "0"}`);
  }
}

export const num = (v, dflt = 0) => {
  if (v instanceof Num) return Number(v.raw);
  if (typeof v === "number") return v;
  if (typeof v === "string" && v.trim() !== "" && !isNaN(Number(v))) return Number(v);
  return dflt;
};
export const str = (v, dflt = "") => (v === undefined || v === null ? dflt : v instanceof Num ? v.raw : String(v));
export const isObj = (v) => v !== null && typeof v === "object" && !Array.isArray(v) && !(v instanceof Num);

export function parse(text) {
  let i = 0;
  const ws = () => { while (i < text.length && " \t\r\n".includes(text[i])) i++; };
  const value = () => {
    ws();
    const c = text[i];
    if (c === "{") {
      i++; const o = {}; ws();
      if (text[i] === "}") { i++; return o; }
      for (;;) {
        ws(); const k = string(); ws();
        if (text[i++] !== ":") throw new Error("expected ':'");
        const v = value();
        if (k !== "__proto__") o[k] = v;
        ws();
        if (text[i] === ",") { i++; continue; }
        if (text[i] === "}") { i++; return o; }
        throw new Error("bad object");
      }
    }
    if (c === "[") {
      i++; const a = []; ws();
      if (text[i] === "]") { i++; return a; }
      for (;;) {
        a.push(value()); ws();
        if (text[i] === ",") { i++; continue; }
        if (text[i] === "]") { i++; return a; }
        throw new Error("bad array");
      }
    }
    if (c === '"') return string();
    if (text.startsWith("true", i)) { i += 4; return true; }
    if (text.startsWith("false", i)) { i += 5; return false; }
    if (text.startsWith("null", i)) { i += 4; return null; }
    const start = i;
    while (i < text.length && /[-+0-9.eE]/.test(text[i])) i++;
    if (start === i) throw new Error(`unexpected '${c}' at ${i}`);
    return new Num(text.slice(start, i));
  };
  const string = () => {
    if (text[i] !== '"') throw new Error("expected string");
    i++; let out = "";
    for (;;) {
      const c = text[i++];
      if (c === undefined) throw new Error("unterminated string");
      if (c === '"') return out;
      if (c !== "\\") { out += c; continue; }
      const e = text[i++];
      if (e === "u") { out += String.fromCharCode(parseInt(text.slice(i, i + 4), 16)); i += 4; }
      else out += { '"': '"', "\\": "\\", "/": "/", b: "\b", f: "\f", n: "\n", r: "\r", t: "\t" }[e];
    }
  };
  const v = value(); ws();
  if (i !== text.length) throw new Error("trailing data");
  return v;
}

const cpCompare = (a, b) => {
  const x = Array.from(a), y = Array.from(b);
  for (let k = 0; k < Math.min(x.length, y.length); k++) {
    const d = x[k].codePointAt(0) - y[k].codePointAt(0);
    if (d) return d;
  }
  return x.length - y.length;
};

function quote(s) {
  let out = '"';
  for (let k = 0; k < s.length; k++) {
    const c = s.charCodeAt(k);
    const ch = s[k];
    if (ch === '"') out += '\\"';
    else if (ch === "\\") out += "\\\\";
    else if (ch === "\n") out += "\\n";
    else if (ch === "\r") out += "\\r";
    else if (ch === "\t") out += "\\t";
    else if (ch === "\b") out += "\\b";
    else if (ch === "\f") out += "\\f";
    else if (c < 0x20 || c > 0x7f) out += "\\u" + c.toString(16).padStart(4, "0");
    else out += ch;
  }
  return out + '"';
}

export function dumps(v) {
  if (v === null || v === undefined) return "null";
  if (v === true) return "true";
  if (v === false) return "false";
  if (v instanceof Num) return v.raw;
  if (typeof v === "number") {
    if (!Number.isInteger(v)) throw new Error("use Num for non-integer numbers");
    return String(v);
  }
  if (typeof v === "string") return quote(v);
  if (Array.isArray(v)) return "[" + v.map(dumps).join(",") + "]";
  const keys = Object.keys(v).filter((k) => v[k] !== undefined).sort(cpCompare);
  return "{" + keys.map((k) => quote(k) + ":" + dumps(v[k])).join(",") + "}";
}

export const bytes = (v) => new TextEncoder().encode(dumps(v));
export const copy = (v) => (v === undefined ? undefined : parse(dumps(v)));
