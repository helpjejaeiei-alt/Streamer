const encoder = new TextEncoder();
export async function sha256(value) {
  return Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', encoder.encode(value))), b => b.toString(16).padStart(2, '0')).join('');
}
export function randomToken() {
  return Array.from(crypto.getRandomValues(new Uint8Array(32)), b => b.toString(16).padStart(2, '0')).join('');
}
export async function seal(value, secret) {
  const key = await aesKey(secret);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, encoder.encode(value));
  return JSON.stringify({ iv: Array.from(iv), data: Array.from(new Uint8Array(ciphertext)) });
}
export async function unseal(value, secret) {
  const envelope = JSON.parse(value);
  return new TextDecoder().decode(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: new Uint8Array(envelope.iv) }, await aesKey(secret), new Uint8Array(envelope.data)));
}
async function aesKey(secret) {
  if (!/^[a-f0-9]{64}$/i.test(secret || '')) throw new Error('Server configuration unavailable');
  return crypto.subtle.importKey('raw', new Uint8Array(secret.match(/../g).map(x => parseInt(x, 16))), 'AES-GCM', false, ['encrypt', 'decrypt']);
}
export function isUnused(info) {
  return info.success === true && ['not used', 'unused'].includes(String(info.status).trim().toLowerCase()) && Number(info.duration) > 0;
}
export function isActiveUser(user, now = Math.floor(Date.now() / 1000)) {
  if (user.success !== true || !Object.hasOwn(user, 'banned')) return false;
  if (![null, '', false, 0, '0'].includes(user.banned)) return false;
  return Array.isArray(user.subscriptions) && user.subscriptions.some(s => Number(s.expiry) > now);
}
export async function validateLicense(license, sellerKey, fetcher = fetch) {
  const call = async (type, fields) => {
    const url = new URL('https://keyauth.win/api/seller/');
    url.search = new URLSearchParams({ sellerkey: sellerKey, type, ...fields });
    let response;
    try { response = await fetcher(url, { redirect: 'manual', signal: AbortSignal.timeout(15000) }); }
    catch { throw new Error('KEYAUTH_TRANSPORT_ERROR'); }
    if (!response.ok) throw new Error('KEYAUTH_HTTP_' + response.status);
    let data;
    try { data = await response.json(); } catch { throw new Error('KEYAUTH_NON_JSON'); }
    return data;
  };
  const info = await call('info', { key: license });
  if (isUnused(info)) return true;
  if (info.success !== true || String(info.status).trim().toLowerCase() !== 'used' || !info.usedby) return false;
  return isActiveUser(await call('userdata', { user: String(info.usedby) }));
}
