import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { DatabaseSync } from 'node:sqlite';
import { randomToken } from '../src/security.mjs';
const original = await readFile(new URL('../src/worker.mjs',import.meta.url),'utf8');
const ps = await readFile(new URL('../src/install.ps1',import.meta.url),'utf8');
const source = original.replace("import installer from './install.ps1';",() => 'const installer = '+JSON.stringify(ps)+';').replace("'./security.mjs'",() => JSON.stringify(new URL('../src/security.mjs',import.meta.url).href)).replace("'./control.mjs'",()=>JSON.stringify(new URL('../src/control.mjs',import.meta.url).href));
const worker = (await import('data:text/javascript;base64,'+Buffer.from(source).toString('base64'))).default;
test('issue, concurrent redemption, download and replay protection through actual SQL',async () => {
  const db = new DatabaseSync(':memory:');
  db.exec(await readFile(new URL('../schema.sql',import.meta.url),'utf8'));
  const oldFetch = globalThis.fetch;
  globalThis.fetch = async url => {
    assert.equal(url.origin,'https://keyauth.win');
    assert.equal(url.searchParams.get('type'),'info');
    return Response.json({success:true,status:'Not Used',duration:'86400'});
  };
  const env = {
    DOWNLOADS_ENABLED:'true',KEYAUTH_SELLER_KEY:'mock-only',LICENSE_ENCRYPTION_KEY:randomToken(),ADMIN_TOKEN:randomToken(),EXE_SHA256:'a'.repeat(64),EXE_OBJECT:'streamer+.exe',
    INSTALLERS:{head:async()=>({size:3}),get:async()=>({size:3,body:new Uint8Array([1,2,3])})},
    DB: {
      prepare(sql) {
        return {
          bind(...args) {
            return {
              async run() { const r=db.prepare(sql).run(...args); return {meta:{changes:r.changes}}; },
              async first() { return db.prepare(sql).get(...args)||null; }
            };
          }
        };
      }
    }
  };
  const post = (path,data,admin) => worker.fetch(new Request('https://installer.example'+path,{method:'POST',headers:{'Content-Type':'application/json',...(admin?{Authorization:'Bearer '+admin}:{})},body:JSON.stringify(data)}),env);
  try {
    assert.equal((await post('/admin/issue',{license:'TEST'})).status,401);
    const issued = await (await post('/admin/issue',{license:'TEST'},env.ADMIN_TOKEN)).json();
    assert.match(issued.token,/^[a-f0-9]{64}$/);
    assert.equal(db.prepare('SELECT license_cipher FROM installs').get().license_cipher.includes('TEST'),false);
    const claims = await Promise.all([post('/redeem',{token:issued.token}),post('/redeem',{token:issued.token})]);
    assert.deepEqual(claims.map(r=>r.status).sort(),[200,403]);
    const claim = await claims.find(r=>r.status===200).json();
    assert.equal(claim.license,'TEST');
    assert.equal(db.prepare('SELECT license_cipher FROM installs').get().license_cipher,'');
    const downloads = await Promise.all([post('/download',{token:claim.downloadToken}),post('/download',{token:claim.downloadToken})]);
    assert.deepEqual(downloads.map(r=>r.status).sort(),[200,403]);
    assert.deepEqual([...new Uint8Array(await downloads.find(r=>r.status===200).arrayBuffer())],[1,2,3]);
    assert.equal((await post('/redeem',{token:issued.token})).status,403);
    const expired = await (await post('/admin/issue',{license:'TEST'},env.ADMIN_TOKEN)).json();
    db.exec('UPDATE installs SET expires_at=1');
    assert.equal((await post('/redeem',{token:expired.token})).status,403);
    env.DOWNLOADS_ENABLED='false';
    assert.equal((await post('/admin/issue',{license:'TEST'},env.ADMIN_TOKEN)).status,503);
  } finally {globalThis.fetch=oldFetch;db.close();}
});
