const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const crypto = require('node:crypto');
const { test } = require('node:test');
const source = fs.readFileSync(process.env.RESUME_SERVER_SOURCE || path.resolve(__dirname, '../apps-script/Code.gs'), 'utf8');
const emptyZip = Buffer.from('UEsFBgAAAAAAAAAAAAAAAAAAAAAAAA==', 'base64');

function server(options = {}) {
  const sent = [];
  const properties = new Map();
  const context = vm.createContext({
    ContentService: { MimeType: { JSON: 'application/json' }, createTextOutput: text => ({ setMimeType() { return this; }, getContent() { return text; } }) },
    PropertiesService: {getScriptProperties: () => ({
      getProperty: key => properties.get(key) || null,
      setProperty: (key,value) => properties.set(key,value),
      deleteProperty: key => properties.delete(key),
      getProperties: () => Object.fromEntries(properties)
    })},
    LockService: {getScriptLock: () => ({waitLock() {},releaseLock() {}})},
    Utilities: {
      DigestAlgorithm: {SHA_256: 'sha256'}, Charset: {UTF_8: 'utf8'},
      getUuid: () => crypto.randomUUID(),
      computeDigest: (algorithm,value) => [...crypto.createHash(algorithm).update(value).digest()],
      computeHmacSha256Signature: (value,key) => [...crypto.createHmac('sha256',key).update(value).digest()],
      base64Decode: value => options.decodedBytes || [...Buffer.from(value, 'base64')],
      newBlob: (bytes, mime, name) => ({ bytes, mime, name, getDataAsString: () => Buffer.from(bytes).toString('utf8') })
    },
    MailApp: {
      sendEmail: (...args) => { if (options.sendError) throw new Error(options.sendError); sent.push(args); },
      getRemainingDailyQuota: () => options.quota ?? 1000
    },
    LanguageApp: { translate: (text, from, to) => `${from}:${to}:${text}` }
  });
  vm.runInContext(source, context);
  const post = data => JSON.parse(context.doPost({ postData: { contents: JSON.stringify(data) } }).getContent());
  function signed(extra={}) {
    const challenge=context.challenge_(extra.submissionId);
    let proof=0;
    while(!crypto.createHash('sha256').update(challenge.token+':'+proof).digest('hex').startsWith('000'))proof++;
    return request({challenge,proof,...extra});
  }
  return { context, sent, post, signed, properties };
}

function request(extra = {}) {
  return { fullname: 'Recovery check', zipBase64: emptyZip.toString('base64'), fileName: '履歴書.zip', ...extra };
}

test('anonymous health check and authorization check do not send mail', () => {
  const app = server();
  assert.equal(JSON.parse(app.context.doGet().getContent()).service, 'yourbright-rirekisho-email');
  assert.equal(app.context.authorizeEmail(), 1000);
  assert.equal(app.sent.length, 0);
});

test('valid uploads reach only staff even when a caller supplies another recipient', () => {
  const app = server();
  assert.equal(app.post(app.signed({ emails: ['attacker@example.org'] })).success, true);
  assert.equal(app.sent.length, 1);
  assert.equal(app.sent[0][0], 'staff@yourbright.co.jp');
  assert.deepEqual(Buffer.from(app.sent[0][3].attachments[0].bytes), emptyZip);
});

test('mail HTML and headers cannot be injected through applicant fields', () => {
  const app = server();
  const name = '<img src=x>\r\nBcc: attacker@example.org';
  assert.equal(app.post(app.signed({ fullname: name, phone: '<script>x</script>', fileName: '../resume\n.zip' })).success, true);
  const mail = app.sent[0];
  assert.doesNotMatch(mail[1], /[\r\n]/);
  assert.doesNotMatch(mail[3].htmlBody, /<img|<script>/);
  assert.match(mail[3].htmlBody, /&lt;img/);
  assert.doesNotMatch(mail[3].attachments[0].name, /[\r\n/\\]/);
});

test('malformed requests and invalid attachments never send mail', () => {
  for (const data of [null, [], {}, request({ zipBase64: '!!!!' }), request({ zipBase64: 'dGVzdA==' })]) {
    const app = server();
    assert.equal(app.post(data).success, false);
    assert.equal(app.sent.length, 0);
  }
  const app = server();
  const result = app.context.doPost({ postData: { contents: '{' } });
  assert.equal(JSON.parse(result.getContent()).success, false);
  assert.equal(app.sent.length, 0);
});

test('the server enforces both encoded and decoded attachment limits', () => {
  const app = server();
  assert.equal(app.post(app.signed({ zipBase64: 'A'.repeat(Math.ceil(20 * 1024 * 1024 / 3) * 4 + 4) })).success, false);
  assert.equal(app.sent.length, 0);
  const oversized = server({ decodedBytes: { length: 20 * 1024 * 1024 + 1 } });
  assert.equal(oversized.post(oversized.signed()).success, false);
  assert.equal(oversized.sent.length, 0);
});

test('mail provider failure is returned as failure', () => {
  const app = server({ sendError: 'Daily quota exceeded' });
  const result = app.post(app.signed());
  assert.equal(result.success, false);
  assert.match(result.error, /Daily quota exceeded/);
});

test('unused translation requests are rejected without consuming translation quota', () => {
  const app=server();
  assert.equal(app.post({action:'translate',text:'hello'}).success,false);
  assert.equal(app.sent.length,0);
});

test('unsigned, forged, expired, and unsolved challenges never send mail', () => {
  const app=server();
  assert.equal(app.post(request()).success,false);
  const signed=app.signed();
  assert.equal(app.post({...signed,proof:-1}).success,false);
  assert.equal(app.post({...signed,challenge:{...signed.challenge,signature:'0'.repeat(64)}}).success,false);
  assert.equal(app.post({...signed,challenge:{...signed.challenge,token:'1700000000000.'+crypto.randomUUID()}}).success,false);
  assert.equal(app.sent.length,0);
});
test('repeated submissions send once, altered submissions are rejected, uncertain sends never retry', () => {
  const app=server(), signed=app.signed();
  assert.equal(app.post(signed).success,true);
  assert.equal(app.post(signed).success,true);
  assert.equal(app.post({...signed,fullname:'Changed'}).success,false);
  assert.equal(app.sent.length,1);
  const failed=server({sendError:'ambiguous provider failure'}), pending=failed.signed();
  assert.equal(failed.post(pending).success,false);
  assert.match(failed.post(pending).error,/unconfirmed/);
  assert.equal([...failed.properties.values()].filter(v=>v.includes('pending')).length,1);
});
test('hourly and daily budgets and sender quota reserve block sends before the provider', () => {
  for(const [count,age] of [[30,1000],[100,7200000]]){
    const app=server();
    for(let i=0;i<count;i++)app.properties.set('submission:fixture'+i,JSON.stringify({time:Date.now()-age}));
    assert.equal(app.post(app.signed()).success,false);
    assert.equal(app.sent.length,0);
  }
  const low=server({quota:249});
  assert.equal(low.post(low.signed()).success,false);
  assert.equal(low.sent.length,0);
});
test('truncated and damaged ZIP central directories never send mail', () => {
  const app=server();
  for(const bytes of [Buffer.from('504b0304','hex'),Buffer.from('504b0506','hex'),Buffer.from('504b0506000000000100010000000000000000000000','hex')]) {
    assert.equal(app.post(app.signed({zipBase64:bytes.toString('base64')})).success,false);
  }
  assert.equal(app.sent.length,0);
});

test('invalid proofs are rejected before large attachments can be decoded', () => {
  const app=server();
  app.context.Utilities.base64Decode=()=>{throw new Error('Must not decode unsigned data');};
  const result=app.post(request());
  assert.match(result.error,/challenge/);
  assert.equal(app.sent.length,0);
});
test('ordinary ZIP entries pass, declared expansion bombs and mismatched headers are rejected', () => {
  const name=Buffer.from('recovery.txt'),body=Buffer.from('synthetic recovery check');
  const local=Buffer.alloc(30);local.writeUInt32LE(0x04034b50);local.writeUInt16LE(20,4);local.writeUInt32LE(body.length,18);local.writeUInt32LE(body.length,22);local.writeUInt16LE(name.length,26);
  const central=Buffer.alloc(46);central.writeUInt32LE(0x02014b50);central.writeUInt16LE(20,4);central.writeUInt16LE(20,6);central.writeUInt32LE(body.length,20);central.writeUInt32LE(body.length,24);central.writeUInt16LE(name.length,28);
  const end=Buffer.alloc(22);end.writeUInt32LE(0x06054b50);end.writeUInt16LE(1,8);end.writeUInt16LE(1,10);end.writeUInt32LE(central.length+name.length,12);end.writeUInt32LE(local.length+name.length+body.length,16);
  const zip=Buffer.concat([local,name,body,central,name,end]);
  const app=server();assert.equal(app.post(app.signed({zipBase64:zip.toString('base64')})).success,true);
  const bad=Buffer.from(zip);bad.writeUInt32LE(2*1024*1024*1024,local.length+name.length+body.length+24);
  assert.equal(app.post(app.signed({zipBase64:bad.toString('base64')})).success,false);
  const mismatch=Buffer.from(zip);mismatch.writeUInt32LE(0,22);
  assert.equal(app.post(app.signed({zipBase64:mismatch.toString('base64')})).success,false);
  assert.equal(app.sent.length,1);
});

test('a new challenge for the same submission ID cannot send a second message', () => {
  const app=server(), first=app.signed();
  assert.equal(app.post(first).success,true);
  const second=app.signed({submissionId:first.challenge.token.split('.')[1]});
  assert.equal(app.post(second).success,true);
  assert.equal(app.sent.length,1);
});
test('issuing challenges after initialization never waits for the sending lock', () => {
  const app=server();app.context.challenge_();
  app.context.LockService.getScriptLock=()=>{throw new Error('Must not acquire established-secret lock');};
  assert.ok(app.context.challenge_().signature);
});
test('a valid signed challenge remains usable during a slow mobile upload', () => {
  const app=server(), data=app.signed(), parts=data.challenge.token.split('.');
  parts[0]=String(Date.now()-30*60000);data.challenge.token=parts.join('.');
  data.challenge.signature=crypto.createHmac('sha256',app.properties.get('challenge-secret')).update(data.challenge.token).digest('hex');
  data.proof=0;while(!crypto.createHash('sha256').update(data.challenge.token+':'+data.proof).digest('hex').startsWith('000'))data.proof++;
  assert.equal(app.post(data).success,true);
});
test('traversal, absolute, Windows, and symlink ZIP entries are rejected', () => {
  for(const filename of ['../escape.txt','/absolute.txt','C:drive.txt','folder/../escape.txt','safe.txt']){
    const name=Buffer.from(filename), local=Buffer.alloc(30), central=Buffer.alloc(46), end=Buffer.alloc(22);
    local.writeUInt32LE(0x04034b50);local.writeUInt16LE(name.length,26);
    central.writeUInt32LE(0x02014b50);central.writeUInt16LE(name.length,28);
    if(filename==='safe.txt')central.writeUInt32LE(0xa000*65536,38);
    end.writeUInt32LE(0x06054b50);end.writeUInt16LE(1,8);end.writeUInt16LE(1,10);end.writeUInt32LE(46+name.length,12);end.writeUInt32LE(30+name.length,16);
    const zip=Buffer.concat([local,name,central,name,end]);
    const app=server();assert.equal(app.post(app.signed({zipBase64:zip.toString('base64')})).success,false);
    assert.equal(app.sent.length,0);
  }
});

test('ZIP compression and alternate names in Unicode extra fields are rejected', () => {
  function archive(method, alternate) {
    const name=Buffer.from('safe.txt'),path=Buffer.from(alternate||'safe.txt');
    const extra=Buffer.alloc(9+path.length);extra.writeUInt16LE(0x7075);extra.writeUInt16LE(5+path.length,2);extra[4]=1;path.copy(extra,9);
    const local=Buffer.alloc(30),central=Buffer.alloc(46),end=Buffer.alloc(22);
    local.writeUInt32LE(0x04034b50);local.writeUInt16LE(method,8);local.writeUInt16LE(name.length,26);local.writeUInt16LE(extra.length,28);
    central.writeUInt32LE(0x02014b50);central.writeUInt16LE(method,10);central.writeUInt16LE(name.length,28);central.writeUInt16LE(extra.length,30);
    end.writeUInt32LE(0x06054b50);end.writeUInt16LE(1,8);end.writeUInt16LE(1,10);end.writeUInt32LE(46+name.length+extra.length,12);end.writeUInt32LE(30+name.length+extra.length,16);
    return Buffer.concat([local,name,extra,central,name,extra,end]).toString('base64');
  }
  const app=server();
  assert.equal(app.post(app.signed({zipBase64:archive(0,'safe.txt')})).success,true);
  assert.equal(app.post(app.signed({zipBase64:archive(0,'../escape.txt')})).success,false);
  assert.equal(app.post(app.signed({zipBase64:archive(8,'safe.txt')})).success,false);
  assert.equal(app.sent.length,1);
});
