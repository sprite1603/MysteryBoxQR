// QRごとの合言葉（URLの#以降）から照合値と鍵を作る。合言葉を知らないと単語も画像も読めない
const MB = (() => {
  const te = new TextEncoder(), td = new TextDecoder();
  const hex = b => [...b].map(x => x.toString(16).padStart(2, '0')).join('');
  const b64 = b => { let s = ''; for (let i = 0; i < b.length; i += 0x8000) s += String.fromCharCode(...b.subarray(i, i + 0x8000)); return btoa(s); };
  const unb64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
  const cache = new Map();
  async function derive(salt, token) {
    const k = salt + '|' + token;
    if (cache.has(k)) return cache.get(k);
    const base = await crypto.subtle.importKey('raw', te.encode(token), 'PBKDF2', false, ['deriveBits']);
    const b = new Uint8Array(await crypto.subtle.deriveBits({ name: 'PBKDF2', salt: te.encode(salt), iterations: 100000, hash: 'SHA-256' }, base, 512));
    const d = { check: hex(b.slice(0, 32)), key: await crypto.subtle.importKey('raw', b.slice(32), 'AES-GCM', false, ['encrypt', 'decrypt']) };
    cache.set(k, d);
    return d;
  }
  // 単語と画像の情報 {w, img:{f, iv, type}} を暗号化して words.json の1件にする
  async function seal(salt, token, payload) {
    const d = await derive(salt, token), iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, d.key, te.encode(JSON.stringify(payload))));
    return { check: d.check, iv: b64(iv), ct: b64(ct) };
  }
  async function open(config, token) {
    const d = await derive(config.salt, token);
    const e = config.words.find(w => w.check === d.check);
    if (!e) return null;
    try {
      const s = td.decode(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(e.iv) }, d.key, unb64(e.ct)));
      try { const p = JSON.parse(s); if (p && typeof p === 'object') return p; } catch (x) {}
      return { w: s };
    } catch (x) { return null; }
  }
  // 画像ファイル本体の暗号化・復号
  async function sealBytes(salt, token, bytes) {
    const d = await derive(salt, token), iv = crypto.getRandomValues(new Uint8Array(12));
    return { iv: b64(iv), data: new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, d.key, bytes)) };
  }
  async function openBytes(salt, token, iv, data) {
    const d = await derive(salt, token);
    return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(iv) }, d.key, data));
  }
  const rand = n => { const a = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789'; return [...crypto.getRandomValues(new Uint8Array(n))].map(x => a[x % a.length]).join(''); };
  const newToken = () => rand(12);
  const newImageName = () => 'img-' + rand(10) + '.bin';
  const esc = s => String(s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
  return { seal, open, sealBytes, openBytes, newToken, newImageName, esc };
})();
