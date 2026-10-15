const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');
const source = fs.readFileSync(process.env.RESUME_SERVER_SOURCE || path.resolve(__dirname, '../apps-script/Code.gs'), 'utf8');
const emptyZip = Buffer.from('UEsFBgAAAAAAAAAAAAAAAAAAAAAAAA==', 'base64');

function server(options = {}) {
  const sent = [];
  const context = vm.createContext({
    ContentService: { MimeType: { JSON: 'application/json' }, createTextOutput: text => ({ setMimeType() { return this; }, getContent() { return text; } }) },
    Utilities: {
      base64Decode: value => options.decodedBytes || [...Buffer.from(value, 'base64')],
      newBlob: (bytes, mime, name) => ({ bytes, mime, name })
    },
    MailApp: {
      sendEmail: (...args) => { if (options.sendError) throw new Error(options.sendError); sent.push(args); },
      getRemainingDailyQuota: () => 50
    },
    LanguageApp: { translate: (text, from, to) => `${from}:${to}:${text}` }
  });
  vm.runInContext(source, context);
  const post = data => JSON.parse(context.doPost({ postData: { contents: JSON.stringify(data) } }).getContent());
  return { context, sent, post };
}

function request(extra = {}) {
  return { fullname: 'Recovery check', zipBase64: emptyZip.toString('base64'), fileName: '履歴書.zip', ...extra };
}

test('anonymous health check and authorization check do not send mail', () => {
  const app = server();
  assert.equal(JSON.parse(app.context.doGet().getContent()).service, 'yourbright-rirekisho-email');
  assert.equal(app.context.authorizeEmail(), 50);
  assert.equal(app.sent.length, 0);
});

test('valid uploads reach only staff even when a caller supplies another recipient', () => {
  const app = server();
  assert.equal(app.post(request({ emails: ['attacker@example.org'] })).success, true);
  assert.equal(app.sent.length, 1);
  assert.equal(app.sent[0][0], 'staff@yourbright.co.jp');
  assert.deepEqual(Buffer.from(app.sent[0][3].attachments[0].bytes), emptyZip);
});

test('mail HTML and headers cannot be injected through applicant fields', () => {
  const app = server();
  const name = '<img src=x>\r\nBcc: attacker@example.org';
  assert.equal(app.post(request({ fullname: name, phone: '<script>x</script>', fileName: '../resume\n.zip' })).success, true);
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
  assert.equal(app.post(request({ zipBase64: 'A'.repeat(Math.ceil(20 * 1024 * 1024 / 3) * 4 + 4) })).success, false);
  assert.equal(app.sent.length, 0);
  const oversized = server({ decodedBytes: { length: 20 * 1024 * 1024 + 1 } });
  assert.equal(oversized.post(request()).success, false);
  assert.equal(oversized.sent.length, 0);
});

test('mail provider failure is returned as failure', () => {
  const app = server({ sendError: 'Daily quota exceeded' });
  const result = app.post(request());
  assert.equal(result.success, false);
  assert.match(result.error, /Daily quota exceeded/);
});

test('the previous translation request contract remains available without sending mail', () => {
  const app = server();
  assert.equal(app.post({ action: 'translate', text: 'hello', sourceLang: 'en', targetLang: 'ja' }).translatedText, 'en:ja:hello');
  assert.equal(app.post({ action: 'translate', text: ' ' }).translatedText, '');
  assert.equal(app.sent.length, 0);
});
