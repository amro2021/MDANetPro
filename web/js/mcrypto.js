// WebCrypto with the same parameters as the Python app (pycryptodome defaults):
// RSA-PSS SHA-256 (salt 32) signatures, RSA-OAEP SHA-1 key wrapping, AES-256-GCM payloads.
const subtle = globalThis.crypto.subtle;

export const b64 = (buf) => {
  const b = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let s = "";
  for (let i = 0; i < b.length; i += 0x8000) s += String.fromCharCode(...b.subarray(i, i + 0x8000));
  return btoa(s);
};
export const unb64 = (text) => Uint8Array.from(atob(String(text).trim()), (c) => c.charCodeAt(0));
export const randomBytes = (n) => globalThis.crypto.getRandomValues(new Uint8Array(n));
export const hex = (buf) => Array.from(new Uint8Array(buf), (x) => x.toString(16).padStart(2, "0")).join("");
export const randomHex = (n) => hex(randomBytes(n));
export const utf8 = (s) => new TextEncoder().encode(s);
export const fromUtf8 = (b) => new TextDecoder().decode(b);

export async function sha256Hex(data) { return hex(await subtle.digest("SHA-256", data)); }

export async function fingerprint(publicPem) {
  return (await sha256Hex(utf8(publicPem.replace(/\s+/g, "")))).slice(0, 20);
}

// pycryptodome's PEM layout: 64-character lines, no trailing newline.
const toPem = (type, der) => `-----BEGIN ${type}-----\n${b64(der).match(/.{1,64}/g).join("\n")}\n-----END ${type}-----`;
const pemBody = (pem) => unb64(pem.split("\n").filter((l) => !l.startsWith("-----")).join("").replace(/\s+/g, ""));

/** A new identity. Private keys are re-imported as non-extractable (one per algorithm). */
export async function generateIdentity() {
  const kp = await subtle.generateKey({ name: "RSA-PSS", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, true, ["sign", "verify"]);
  const pkcs8 = await subtle.exportKey("pkcs8", kp.privateKey);
  const spki = await subtle.exportKey("spki", kp.publicKey);
  return {
    publicPem: toPem("PUBLIC KEY", spki),
    signKey: await subtle.importKey("pkcs8", pkcs8, { name: "RSA-PSS", hash: "SHA-256" }, false, ["sign"]),
    decryptKey: await subtle.importKey("pkcs8", pkcs8, { name: "RSA-OAEP", hash: "SHA-1" }, false, ["decrypt"]),
  };
}

const pssCache = new Map();
const oaepCache = new Map();
async function pssKey(pem) {
  if (!pssCache.has(pem)) pssCache.set(pem, await subtle.importKey("spki", pemBody(pem), { name: "RSA-PSS", hash: "SHA-256" }, false, ["verify"]));
  return pssCache.get(pem);
}
async function oaepKey(pem) {
  if (!oaepCache.has(pem)) oaepCache.set(pem, await subtle.importKey("spki", pemBody(pem), { name: "RSA-OAEP", hash: "SHA-1" }, false, ["encrypt"]));
  return oaepCache.get(pem);
}

export async function sign(identity, data) {
  return b64(await subtle.sign({ name: "RSA-PSS", saltLength: 32 }, identity.signKey, data));
}
export async function verify(publicPem, data, signatureB64) {
  try { return await subtle.verify({ name: "RSA-PSS", saltLength: 32 }, await pssKey(publicPem), unb64(signatureB64), data); }
  catch { return false; }
}
export async function oaepEncrypt(publicPem, data) {
  return new Uint8Array(await subtle.encrypt({ name: "RSA-OAEP" }, await oaepKey(publicPem), data));
}
export async function oaepDecrypt(identity, data) {
  return new Uint8Array(await subtle.decrypt({ name: "RSA-OAEP" }, identity.decryptKey, data));
}
export async function aesGcmEncrypt(key, plain) {
  const nonce = randomBytes(12);
  const k = await subtle.importKey("raw", key, "AES-GCM", false, ["encrypt"]);
  const out = new Uint8Array(await subtle.encrypt({ name: "AES-GCM", iv: nonce, tagLength: 128 }, k, plain));
  return { nonce, ct: out.slice(0, out.length - 16), tag: out.slice(out.length - 16) };
}
export async function aesGcmDecrypt(key, nonce, ct, tag) {
  const k = await subtle.importKey("raw", key, "AES-GCM", false, ["decrypt"]);
  const joined = new Uint8Array(ct.length + tag.length); joined.set(ct); joined.set(tag, ct.length);
  return new Uint8Array(await subtle.decrypt({ name: "AES-GCM", iv: nonce, tagLength: 128 }, k, joined));
}
