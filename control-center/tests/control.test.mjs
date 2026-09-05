import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {DatabaseSync} from 'node:sqlite';
import {control,defaults,validConfig,customerCommand} from '../src/control.mjs';
import {randomToken} from '../src/security.mjs';
test('configuration validation rejects unsafe and unknown fields',()=>{
  assert.equal(validConfig(defaults),true);
  for(const c of [{...defaults,fovSize:641},{...defaults,sensitivity:Infinity},{...defaults,aim:'true'},{...defaults,command:'anything'},{...defaults,aimButton:'Middle'}])assert.equal(validConfig(c),false);
  const command=customerCommand('https://installer.example','a'.repeat(64),'b'.repeat(64));
  assert.ok(command.startsWith('powershell '));
  assert.ok(!command.includes('ADMIN_TOKEN'));
});
test('web and device sessions isolate keys; CSRF, revisions, ack and rate limit',async()=>{
  const db=new DatabaseSync(':memory:');db.exec(await readFile(new URL('../control-schema.sql',import.meta.url),'utf8'));
  db.exec(await readFile(new URL('../schema.sql',import.meta.url),'utf8'));
  const old=globalThis.fetch;
  globalThis.fetch=async()=>Response.json({success:true,status:'Not Used',duration:100});
  const env={KEYAUTH_SELLER_KEY:'mock',LICENSE_ENCRYPTION_KEY:randomToken(),DOWNLOADS_ENABLED:'true',EXE_OBJECT:'test',INSTALLERS:{head:async()=>({})},DB:{prepare(sql){return {bind(...args){return {async run(){return {meta:{changes:db.prepare(sql).run(...args).changes}};},async first(){return db.prepare(sql).get(...args)||null;}};}};}}};
  const req=(path,data,headers={})=>control(new Request('https://installer.example/control/'+path,{method:data===undefined?'GET':'POST',headers:{Origin:'https://installer.example','Content-Type':'application/json',...headers},...(data===undefined?{}:{body:JSON.stringify(data)})}),env,'test installer');
  try{
    const a=await req('web/login',{license:'KEY-A'}), b=await req('web/login',{license:'KEY-B'});
    const cookieA=a.headers.get('set-cookie').split(';')[0],cookieB=b.headers.get('set-cookie').split(';')[0];
    const desired={...defaults,aim:true,sensitivity:0.25};
    assert.equal((await req('web/config',{config:desired,revision:1},{Cookie:cookieA,Origin:'https://evil.example'})).status,403);
    assert.equal((await req('web/config',{config:desired,revision:1},{Cookie:cookieA})).status,200);
    assert.equal((await req('web/config',{config:desired,revision:1},{Cookie:cookieA})).status,409);
    const stateB=await (await req('web/state',undefined,{Cookie:cookieB})).json();assert.equal(stateB.config.aim,false);
    const device=await (await req('device/login',{license:'KEY-A'})).json();
    const first=await (await req('device/sync',{actual:defaults,appliedRevision:0},{Authorization:'Bearer '+device.token})).json();
    assert.deepEqual(first.config,desired);assert.equal(first.revision,2);
    const before=await (await req('web/state',undefined,{Cookie:cookieA})).json();assert.equal(before.device.appliedRevision,0);
    await req('device/sync',{actual:desired,appliedRevision:2},{Authorization:'Bearer '+device.token});
    const after=await (await req('web/state',undefined,{Cookie:cookieA})).json();assert.equal(after.device.appliedRevision,2);assert.equal(after.device.online,true);
    assert.equal((await req('device/sync',{actual:desired,appliedRevision:2},{Cookie:cookieA})).status,401);
    await req('web/logout',{}, {Cookie:cookieA});assert.equal((await req('web/state',undefined,{Cookie:cookieA})).status,401);
    let last;for(let i=0;i<13;i++)last=await req('web/login',{license:'KEY-A'});assert.equal(last.status,429);
  }finally{globalThis.fetch=old;db.close();}
});
