import test from 'node:test';
import assert from 'node:assert/strict';
import { seal, unseal, randomToken, validateLicense, isActiveUser } from '../src/security.mjs';
test('encrypted license round-trips Unicode; different IVs; tampering fails', async () => {
  const secret = randomToken(), license = 'TEST-ทดสอบ';
  const a = await seal(license, secret), b = await seal(license, secret);
  assert.notEqual(a, b);
  assert.equal(await unseal(a, secret), license);
  const altered = JSON.parse(a); altered.data[0] ^= 1;
  await assert.rejects(unseal(JSON.stringify(altered), secret));
  await assert.rejects(unseal(a, randomToken()));
});
test('unused license check does not initialize or activate license', async () => {
  const calls = [];
  const valid = await validateLicense('TEST', 'fake-seller', async url => {
    calls.push(url.searchParams.get('type'));
    return Response.json({success:true,status:'Not Used',duration:'86400'});
  });
  assert.equal(valid, true); assert.deepEqual(calls, ['info']);
});
test('used license checks active subscription and banned user', async () => {
  for (const banned of ['', 'ban reason']) {
    const replies = [{success:true,status:'Used',usedby:'TEST'}, {success:true,banned,subscriptions:[{expiry:4102444800}]}];
    const calls = [];
    const valid = await validateLicense('TEST','fake',async url => {
      calls.push(url.searchParams.get('type')); return Response.json(replies.shift());
    });
    assert.equal(valid, banned === ''); assert.deepEqual(calls, ['info','userdata']);
  }
});
test('unknown license statuses and failed upstream requests fail closed', async () => {
  for (const status of ['Banned','','surprise']) assert.equal(await validateLicense('TEST','fake',async () => Response.json({success:true,status})), false);
  await assert.rejects(validateLicense('TEST','fake',async () => new Response('',{status:503})));
  assert.equal(isActiveUser({success:true,banned:'',subscriptions:[{expiry:1}]}),false);
  assert.equal(isActiveUser({success:true,subscriptions:[{expiry:4102444800}]}),false);
});
