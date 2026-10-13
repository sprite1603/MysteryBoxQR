// QRごとの合言葉（URLの#以降）から照合値と鍵を作る。合言葉を知らないと単語は読めない
const MB = (() => {
  const te = new TextEncoder(), td = new TextDecoder();
  const hex = b => [...b].map(x => x.toString(16).padStart(2, '0')).join('');
  const b64 = b => btoa(String.fromCharCode(...b));
  const unb64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
  async function derive(salt, token) {
    const base = await crypto.subtle.importKey('raw', te.encode(token), 'PBKDF2', false, ['deriveBits']);
    const b = new Uint8Array(await crypto.subtle.deriveBits({ name: 'PBKDF2', salt: te.encode(salt), iterations: 100000, hash: 'SHA-256' }, base, 512));
    return { check: hex(b.slice(0, 32)), key: await crypto.subtle.importKey('raw', b.slice(32), 'AES-GCM', false, ['encrypt', 'decrypt']) };
  }
  async function seal(salt, token, word) {
    const d = await derive(salt, token), iv = crypto.getRandomValues(new Uint8Array(12));
    return { check: d.check, iv: b64(iv), ct: b64(new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, d.key, te.encode(word)))) };
  }
  async function open(config, token) {
    const d = await derive(config.salt, token);
    const e = config.words.find(w => w.check === d.check);
    if (!e) return null;
    try { return td.decode(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(e.iv) }, d.key, unb64(e.ct))); } catch (x) { return null; }
  }
  const newToken = () => { const a = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789'; return [...crypto.getRandomValues(new Uint8Array(12))].map(n => a[n % a.length]).join(''); };
  const esc = s => String(s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
  return { seal, open, newToken, esc };
})();
