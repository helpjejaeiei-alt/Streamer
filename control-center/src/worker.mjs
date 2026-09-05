import installer from './install.ps1';
import { sha256, randomToken, seal, unseal, validateLicense } from './security.mjs';
import { control } from './control.mjs';
const json = (data, status = 200) => Response.json(data, { status, headers: { 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' } });
function ready(env) {
  return env.DOWNLOADS_ENABLED === 'true' && env.KEYAUTH_SELLER_KEY && /^[a-f0-9]{64}$/i.test(env.LICENSE_ENCRYPTION_KEY || '') && env.ADMIN_TOKEN?.length >= 32 && /^[a-f0-9]{64}$/i.test(env.EXE_SHA256 || '');
}
async function body(request) {
  if (Number(request.headers.get('content-length')) > 4096) throw new Error('Invalid request');
  const data = await request.text();
  if (data.length > 4096) throw new Error('Invalid request');
  return JSON.parse(data);
}
function tokenValid(token) { return typeof token === 'string' && /^[a-f0-9]{64}$/.test(token); }
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.protocol !== 'https:') return json({ error: 'HTTPS required' }, 400);
    if (url.pathname.startsWith('/control/')) return control(request,env,installer);
    if (request.method==='GET' && (url.pathname==='/' || url.pathname.startsWith('/assets/'))) {
      const response=await env.ASSETS.fetch(request);
      const secured=new Response(response.body,response);
      secured.headers.set('Content-Security-Policy',"default-src 'self'; script-src 'self'; style-src 'self'; font-src 'self'; img-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'");
      secured.headers.set('Referrer-Policy','no-referrer');
      return secured;
    }
    if (request.method === 'GET' && url.pathname === '/health') return json({ service: 'streamer-install-api', ready: Boolean(ready(env)) });
    if (request.method === 'POST' && url.pathname === '/admin/validate') {
      if (!env.ADMIN_TOKEN || !env.KEYAUTH_SELLER_KEY) return json({ error: 'Server configuration unavailable' }, 503);
      if (await sha256(request.headers.get('authorization') || '') !== await sha256('Bearer ' + env.ADMIN_TOKEN)) return json({ error: 'Unauthorized' }, 401);
      try {
        const data = await body(request);
        if (typeof data.license !== 'string' || !data.license.trim() || data.license.length > 256) return json({ error: 'Invalid license' }, 400);
        return json({ eligible: await validateLicense(data.license.trim(), env.KEYAUTH_SELLER_KEY) });
      } catch (error) { return json({ error: 'License verification unavailable', code: /^KEYAUTH_[A-Z0-9_]+$/.test(error.message || '') ? error.message : 'VERIFICATION_FAILED' }, 503); }
    }
    if (!ready(env)) return json({ error: 'Installation service is not ready' }, 503);
    if (url.pathname === '/install.ps1' && request.method === 'GET') return new Response(installer, { headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' } });
    try {
      if (request.method !== 'POST') return json({ error: 'Not found' }, 404);
      if (url.pathname === '/admin/issue') {
        const supplied = request.headers.get('authorization') || '';
        if (await sha256(supplied) !== await sha256('Bearer ' + env.ADMIN_TOKEN)) return json({ error: 'Unauthorized' }, 401);
        const data = await body(request);
        const license = typeof data.license === 'string' ? data.license.trim() : '';
        if (!license || license.length > 256 || /[\r\n\x00]/.test(license)) return json({ error: 'Invalid license' }, 400);
        if (!await validateLicense(license, env.KEYAUTH_SELLER_KEY)) return json({ error: 'License is invalid, banned, or expired' }, 403);
        if (!await env.INSTALLERS.head(env.EXE_OBJECT)) return json({ error: 'Installer unavailable' }, 503);
        const token = randomToken();
        const expires = Math.floor(Date.now() / 1000) + 1800;
        await env.DB.prepare('INSERT INTO installs(token_hash,license_cipher,expires_at) VALUES(?,?,?)').bind(await sha256(token), await seal(license, env.LICENSE_ENCRYPTION_KEY), expires).run();
        return json({ token, expiresAt: new Date(expires * 1000).toISOString(), installerSha256: await sha256(installer) });
      }
      if (url.pathname === '/redeem') {
        const { token } = await body(request);
        if (!tokenValid(token)) return json({ error: 'Invalid token' }, 403);
        const hash = await sha256(token), now = Math.floor(Date.now() / 1000);
        const row = await env.DB.prepare('SELECT license_cipher FROM installs WHERE token_hash=? AND state=0 AND expires_at>?').bind(hash, now).first();
        if (!row) return json({ error: 'Token expired or already used' }, 403);
        const license = await unseal(row.license_cipher, env.LICENSE_ENCRYPTION_KEY);
        if (!await validateLicense(license, env.KEYAUTH_SELLER_KEY)) return json({ error: 'License is no longer eligible' }, 403);
        const downloadToken = randomToken();
        const claim = await env.DB.prepare("UPDATE installs SET state=1,license_cipher='',download_hash=?,download_expires=? WHERE token_hash=? AND state=0 AND expires_at>?").bind(await sha256(downloadToken), now + 600, hash, now).run();
        if (claim.meta.changes !== 1) return json({ error: 'Token expired or already used' }, 403);
        return json({ license, downloadToken, sha256: env.EXE_SHA256 });
      }
      if (url.pathname === '/download') {
        const { token } = await body(request);
        if (!tokenValid(token)) return json({ error: 'Invalid token' }, 403);
        const hash = await sha256(token), now = Math.floor(Date.now() / 1000);
        const eligible = await env.DB.prepare('SELECT token_hash FROM installs WHERE download_hash=? AND state=1 AND download_expires>?').bind(hash, now).first();
        if (!eligible) return json({ error: 'Download token expired or already used' }, 403);
        const object = await env.INSTALLERS.get(env.EXE_OBJECT);
        if (!object) return json({ error: 'Installer unavailable' }, 503);
        const claim = await env.DB.prepare('DELETE FROM installs WHERE download_hash=? AND state=1 AND download_expires>? RETURNING token_hash').bind(hash, now).first();
        if (!claim) return json({ error: 'Download token already used' }, 403);
        return new Response(object.body, { headers: { 'Content-Type': 'application/octet-stream', 'Content-Length': String(object.size), 'Cache-Control': 'private, no-store' } });
      }
      return json({ error: 'Not found' }, 404);
    } catch {
      // Never include upstream URLs, license keys, or exception text in client responses/logs.
      return json({ error: 'Unable to complete installation request' }, 503);
    }
  },
  async scheduled(event, env) {
    await env.DB.prepare('DELETE FROM installs WHERE expires_at < ?').bind(Math.floor(Date.now() / 1000) - 3600).run();
    for(const table of ['control_sessions','control_limits'])await env.DB.prepare(`DELETE FROM ${table} WHERE expires < ?`).bind(Math.floor(Date.now()/1000)).run();
    await env.DB.prepare('DELETE FROM control_devices WHERE seen < ?').bind(Math.floor(Date.now()/1000)-86400).run();
  }
};
