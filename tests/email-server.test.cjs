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
      newBlob: (bytes, mime, name) => ({ bytes, mime, name })
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
    const challenge=context.challenge_();
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

test('the previous translation request contract remains available without sending mail', () => {
  const app = server();
  assert.equal(app.post({ action: 'translate', text: 'hello', sourceLang: 'en', targetLang: 'ja' }).translatedText, 'en:ja:hello');
  assert.equal(app.post({ action: 'translate', text: ' ' }).translatedText, '');
  assert.equal(app.sent.length, 0);
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
