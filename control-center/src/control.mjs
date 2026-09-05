import { sha256, randomToken, seal, unseal, validateLicense } from './security.mjs';
export const defaults = { aim:false, fov:false, smoothing:false, sticky:false, fovSize:640, sensitivity:0.5, aimButton:'Right', menuVisible:false };
export function validConfig(c) {
  return c && typeof c==='object' && !Array.isArray(c) && Object.keys(c).length===8 && ['aim','fov','smoothing','sticky','menuVisible'].every(k=>typeof c[k]==='boolean') && Number.isInteger(c.fovSize) && c.fovSize>=40 && c.fovSize<=640 && Number.isFinite(c.sensitivity) && c.sensitivity>=0.01 && c.sensitivity<=1 && ['Left','Right'].includes(c.aimButton);
}
const reply=(data,status=200,headers={})=>Response.json(data,{status,headers:{'Cache-Control':'no-store','X-Content-Type-Options':'nosniff',...headers}});
const now=()=>Math.floor(Date.now()/1000);
async function read(request) {
  if(Number(request.headers.get('content-length'))>4096) throw Error('request');
  const reader=request.body?.getReader(); if(!reader) return {};
  const chunks=[];let size=0;
  while(true){const {done,value}=await reader.read();if(done)break;size+=value.length;if(size>4096){await reader.cancel();throw Error('request');}chunks.push(value);}
  const bytes=new Uint8Array(size);let i=0;for(const c of chunks){bytes.set(c,i);i+=c.length;}
  return JSON.parse(new TextDecoder().decode(bytes));
}
async function limited(env,key,max,seconds=60){
  const id=await sha256(key+':'+Math.floor(now()/seconds));
  const r=await env.DB.prepare('INSERT INTO control_limits(id,count,expires) VALUES(?,1,?) ON CONFLICT(id) DO UPDATE SET count=count+1 RETURNING count').bind(id,now()+seconds*2).first();
  return r.count>max;
}
async function authenticate(request,env,kind){
  const token=kind==='web' ? (request.headers.get('cookie')||'').match(/(?:^|;\s*)streamer_sid=([a-f0-9]{64})(?:;|$)/)?.[1] : (request.headers.get('authorization')||'').match(/^Bearer ([a-f0-9]{64})$/)?.[1];
  if(!token)return null;
  const hash=await sha256(token);
  const s=await env.DB.prepare('SELECT * FROM control_sessions WHERE token_hash=? AND kind=? AND expires>?').bind(hash,kind,now()).first();
  if(!s)return null;
  if(s.checked<now()-60){
    if(!await validateLicense(await unseal(s.license_cipher,env.LICENSE_ENCRYPTION_KEY),env.KEYAUTH_SELLER_KEY)){
      await env.DB.prepare('DELETE FROM control_sessions WHERE token_hash=?').bind(hash).run();return null;
    }
    await env.DB.prepare('UPDATE control_sessions SET checked=? WHERE token_hash=?').bind(now(),hash).run();
  }
  return s;
}
function base64Utf8(text){
  const bytes=new TextEncoder().encode(text);
  let binary='';
  for(const byte of bytes)binary+=String.fromCharCode(byte);
  return btoa(binary);
}
export function customerCommand(origin,token,scriptHash){
  const script=`$ErrorActionPreference='Stop'\nAdd-Type -AssemblyName System.Windows.Forms\nfunction Show-InstallMessage([string]$Text,[string]$Title,[string]$Icon){[Windows.Forms.MessageBox]::Show($Text,$Title,[Windows.Forms.MessageBoxButtons]::OK,[Windows.Forms.MessageBoxIcon]::$Icon)|Out-Null}\n$p=Join-Path ([IO.Path]::GetTempPath()) ([Guid]::NewGuid().ToString('N')+'.ps1')\ntry {\n$w=New-Object Net.WebClient\ntry{$w.DownloadFile('${origin}/install.ps1',$p)}finally{$w.Dispose()}\nif((Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash -ne '${scriptHash}'){throw 'Verification failed'}\n$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value\n$q=$p.Replace("'","''")\n$r="& ([scriptblock]::Create([IO.File]::ReadAllText('"+$q+"'))) -Api '${origin}' -Token '${token}' -ExpectedSid '"+$sid+"'"\n$a='-NoProfile -EncodedCommand '+[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($r))\n$x=Start-Process powershell.exe -Verb RunAs -ArgumentList $a -Wait -PassThru\nif($x.ExitCode -ne 0){Show-InstallMessage 'ติดตั้งไม่สำเร็จ กรุณาสร้างคำสั่งใหม่แล้วลองอีกครั้ง' 'streamer+' 'Error'}\n}catch{Show-InstallMessage 'ติดตั้งไม่สำเร็จ กรุณาสร้างคำสั่งใหม่แล้วลองอีกครั้ง' 'streamer+' 'Error'}finally{if(Test-Path -LiteralPath $p){Remove-Item -LiteralPath $p -Force}}`;
  return `powershell "iex ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${base64Utf8(script)}')))"`;
}
export async function control(request,env,installer){
  const url=new URL(request.url),path=url.pathname;
  const isWeb=path.startsWith('/control/web/');
  if(isWeb && request.method==='POST' && request.headers.get('origin')!==url.origin)return reply({error:'Origin rejected'},403);
  try{
    if(request.method==='POST' && ['/control/web/login','/control/device/login'].includes(path)){
      if(await limited(env,'login:'+(request.headers.get('cf-connecting-ip')||'unknown'),12))return reply({error:'ลองหลายครั้งเกินไป กรุณารอหนึ่งนาที'},429);
      const {license}=await read(request);
      if(typeof license!=='string'||!license.trim()||license.length>256)return reply({error:'กรุณากรอก key ให้ครบ'},400);
      if(!await validateLicense(license.trim(),env.KEYAUTH_SELLER_KEY))return reply({error:'key ไม่ถูกต้อง หมดอายุ หรือถูกระงับ'},401);
      const token=randomToken(),id=await sha256(license.trim()),kind=isWeb?'web':'device',expires=now()+43200;
      await env.DB.prepare('INSERT INTO control_sessions VALUES(?,?,?,?,?,?)').bind(await sha256(token),id,await seal(license.trim(),env.LICENSE_ENCRYPTION_KEY),kind,expires,now()).run();
      await env.DB.prepare('INSERT OR IGNORE INTO control_settings VALUES(?,1,?)').bind(id,JSON.stringify(defaults)).run();
      return isWeb?reply({ok:true,expires},200,{'Set-Cookie':`streamer_sid=${token}; Path=/control/web; HttpOnly; Secure; SameSite=Strict; Max-Age=43200`}):reply({token,expires});
    }
    const session=await authenticate(request,env,isWeb?'web':'device');
    if(!session)return reply({error:'กรุณาเข้าสู่ระบบอีกครั้ง'},401);
    if(path==='/control/web/logout'&&request.method==='POST'){
      await env.DB.prepare('DELETE FROM control_sessions WHERE token_hash=?').bind(session.token_hash).run();
      return reply({ok:true},200,{'Set-Cookie':'streamer_sid=; Path=/control/web; HttpOnly; Secure; SameSite=Strict; Max-Age=0'});
    }
    if(path==='/control/web/state'&&request.method==='GET'){
      const row=await env.DB.prepare('SELECT revision,config FROM control_settings WHERE license_id=?').bind(session.license_id).first();
      const device=await env.DB.prepare('SELECT seen,applied,actual FROM control_devices WHERE license_id=? ORDER BY seen DESC LIMIT 1').bind(session.license_id).first();
      return reply({revision:row.revision,config:JSON.parse(row.config),device:device?{online:device.seen>now()-15,lastSeen:device.seen,appliedRevision:device.applied,actual:JSON.parse(device.actual)}:null});
    }
    if(path==='/control/web/config'&&request.method==='POST'){
      if(await limited(env,'save:'+session.license_id,60))return reply({error:'กรุณารอสักครู่แล้วบันทึกอีกครั้ง'},429);
      const {config,revision}=await read(request);
      if(!validConfig(config)||!Number.isInteger(revision))return reply({error:'ค่าตั้งไม่ถูกต้อง'},400);
      const row=await env.DB.prepare('UPDATE control_settings SET config=?,revision=revision+1 WHERE license_id=? AND revision=? RETURNING revision').bind(JSON.stringify(config),session.license_id,revision).first();
      if(!row)return reply({error:'มีการแก้ไขจากอีกหน้าต่าง กรุณาโหลดค่าล่าสุดก่อน'},409);
      return reply({revision:row.revision});
    }
    if(path==='/control/web/install'&&request.method==='POST'){
      if(env.DOWNLOADS_ENABLED!=='true')return reply({error:'ยังไม่เปิดการติดตั้ง'},503);
      if(await limited(env,'install:'+session.license_id,3,1800))return reply({error:'สร้างคำสั่งครบโควตาแล้ว กรุณารอ 30 นาที'},429);
      const license=await unseal(session.license_cipher,env.LICENSE_ENCRYPTION_KEY);
      if(!await validateLicense(license,env.KEYAUTH_SELLER_KEY))return reply({error:'สิทธิ์ใช้งานไม่พร้อม'},403);
      if(!await env.INSTALLERS.head(env.EXE_OBJECT))return reply({error:'ตัวติดตั้งยังไม่พร้อม'},503);
      const token=randomToken(),expires=now()+1800;
      await env.DB.prepare('INSERT INTO installs(token_hash,license_cipher,expires_at) VALUES(?,?,?)').bind(await sha256(token),await seal(license,env.LICENSE_ENCRYPTION_KEY),expires).run();
      const installOrigin = env.INSTALL_API_ORIGIN || url.origin;
      return reply({command:customerCommand(installOrigin,token,await sha256(installer)),expires});
    }
    if(path==='/control/device/sync'&&request.method==='POST'){
      const {actual,appliedRevision}=await read(request);
      if(!validConfig(actual)||!Number.isInteger(appliedRevision)||appliedRevision<0)return reply({error:'Invalid state'},400);
      await env.DB.prepare('INSERT INTO control_devices VALUES(?,?,?,?,?) ON CONFLICT(token_hash) DO UPDATE SET seen=excluded.seen,applied=excluded.applied,actual=excluded.actual').bind(session.token_hash,session.license_id,now(),appliedRevision,JSON.stringify(actual)).run();
      const row=await env.DB.prepare('SELECT revision,config FROM control_settings WHERE license_id=?').bind(session.license_id).first();
      return reply({revision:row.revision,config:JSON.parse(row.config)});
    }
    return reply({error:'Not found'},404);
  }catch{return reply({error:'เชื่อมต่อบริการไม่สำเร็จ กรุณาลองอีกครั้ง'},503);}
}
