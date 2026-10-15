// YourBright resume email server. Deploy as yamashita.hayato@yourbright.co.jp.
// Only the send-mail scope is required; the script cannot read the Gmail inbox.
var RESUME_RECIPIENT = 'staff@yourbright.co.jp';
var RESUME_VERSION = '2026-10-15';
var MAX_ZIP_BYTES = 20 * 1024 * 1024;

function jsonResponse_(value) {
  return ContentService.createTextOutput(JSON.stringify(value))
    .setMimeType(ContentService.MimeType.JSON);
}

function doGet(e) {
  if (e && e.parameter && e.parameter.action === 'challenge') return jsonResponse_({success: true, challenge: challenge_()});
  return jsonResponse_({success: true, service: 'yourbright-rirekisho-email', version: RESUME_VERSION});
}

function escapeHtml_(value) {
  return String(value).replace(/[&<>"']/g, function (character) {
    return {'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[character];
  });
}

// A signed, ten-minute, single-use proof-of-work challenge adds bot cost without
// requiring an applicant login. Persistent limits protect the sender quota.
function hex_(bytes) { return bytes.map(function (b) { return ('0' + (b & 255).toString(16)).slice(-2); }).join(''); }
function digest_(value) { return hex_(Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, value, Utilities.Charset.UTF_8)); }
function challenge_() {
  var lock = LockService.getScriptLock(); lock.waitLock(10000);
  try {
    var props = PropertiesService.getScriptProperties();
    var secret = props.getProperty('challenge-secret');
    if (!secret) { secret = Utilities.getUuid() + Utilities.getUuid(); props.setProperty('challenge-secret', secret); }
    var token = Date.now() + '.' + Utilities.getUuid();
    return {token: token, signature: hex_(Utilities.computeHmacSha256Signature(token, secret)), prefix: '000'};
  } finally { lock.releaseLock(); }
}
function verifyChallenge_(data) {
  var c = data.challenge;
  if (!c || typeof c.token !== 'string' || !/^\d{13}\.[a-f0-9-]{36}$/.test(c.token) ||
      typeof c.signature !== 'string' || !/^[a-f0-9]{64}$/.test(c.signature) ||
      !Number.isInteger(data.proof) || data.proof < 0 || data.proof > 2000000) throw new Error('Invalid submission challenge.');
  var age = Date.now() - Number(c.token.split('.')[0]);
  var secret = PropertiesService.getScriptProperties().getProperty('challenge-secret');
  if (age < 0 || age > 600000 || !secret ||
      hex_(Utilities.computeHmacSha256Signature(c.token, secret)) !== c.signature ||
      digest_(c.token + ':' + data.proof).slice(0, 3) !== '000') throw new Error('Submission challenge expired or invalid.');
}
function sendOnce_(data, send) {
  verifyChallenge_(data);
  var lock = LockService.getScriptLock(); lock.waitLock(10000);
  try {
    var props = PropertiesService.getScriptProperties(), now = Date.now();
    var key = 'submission:' + data.challenge.token;
    var fingerprint = digest_(JSON.stringify([data.zipBase64, data.fullname, data.furigana, data.nationality, data.visa, data.phone, data.email, data.fileName]));
    var previous = props.getProperty(key);
    if (previous) {
      var receipt = JSON.parse(previous);
      if (receipt.hash !== fingerprint) throw new Error('Submission already used with different content.');
      if (receipt.status !== 'sent') throw new Error('Delivery is unconfirmed. Check with staff before sending again.');
      return;
    }
    var all = props.getProperties(), hourCount = 0, dayCount = 0;
    Object.keys(all).forEach(function (name) {
      if (name.indexOf('submission:') !== 0) return;
      var row = JSON.parse(all[name]);
      if (now - row.time > 86400000) { props.deleteProperty(name); return; }
      dayCount++; if (now - row.time < 3600000) hourCount++;
    });
    if (hourCount >= 30 || dayCount >= 100 || MailApp.getRemainingDailyQuota() < 250) throw new Error('Email limit reached. Download the ZIP and contact staff.');
    // Record before contacting the provider: uncertain failures must never retry a send.
    var record = {time: now, hash: fingerprint, status: 'pending'};
    props.setProperty(key, JSON.stringify(record));
    send();
    record.status = 'sent'; props.setProperty(key, JSON.stringify(record));
  } finally { lock.releaseLock(); }
}

// Check the central directory and every referenced local entry without inflating
// untrusted compressed bytes (which could be a decompression bomb).
function validateZip_(bytes) {
  function u16(i) { return (bytes[i] & 255) + (bytes[i + 1] & 255) * 256; }
  function u32(i) { return u16(i) + u16(i + 2) * 65536; }
  function fail() { throw new Error('Invalid ZIP structure.'); }
  var end = -1;
  for (var i = bytes.length - 22; i >= Math.max(0, bytes.length - 65557); i--) {
    if (u32(i) === 0x06054b50 && i + 22 + u16(i + 20) === bytes.length) { end = i; break; }
  }
  if (end < 0 || u16(end + 4) || u16(end + 6) || u16(end + 8) !== u16(end + 10)) fail();
  var count = u16(end + 10), size = u32(end + 12), start = u32(end + 16), pos = start;
  if (count === 65535 || start + size !== end) fail();
  for (var n = 0; n < count; n++) {
    if (pos + 46 > end || u32(pos) !== 0x02014b50 || u16(pos + 34) || (u16(pos + 8) & 1)) fail();
    var nameLength = u16(pos + 28), entryEnd = pos + 46 + nameLength + u16(pos + 30) + u16(pos + 32);
    var local = u32(pos + 42), compressed = u32(pos + 20);
    if (entryEnd > end || local + 30 > start || u32(local) !== 0x04034b50 || u16(local + 26) !== nameLength ||
        local + 30 + nameLength + u16(local + 28) + compressed > start) fail();
    for (var j = 0; j < nameLength; j++) if (bytes[local + 30 + j] !== bytes[pos + 46 + j]) fail();
    pos = entryEnd;
  }
  if (pos !== end || (!count && start !== 0)) fail();
}

function attachment_(data) {
  var encoded = data.zipBase64;
  if (typeof encoded !== 'string' || !encoded || encoded.length % 4 !== 0 ||
      encoded.length > Math.ceil(MAX_ZIP_BYTES / 3) * 4 ||
      !/^[A-Za-z0-9+/]*={0,2}$/.test(encoded)) {
    throw new Error('Invalid ZIP attachment or attachment exceeds 20 MB.');
  }
  var bytes = Utilities.base64Decode(encoded);
  if (bytes.length > MAX_ZIP_BYTES || bytes.length < 4 ||
      (bytes[0] & 255) !== 80 || (bytes[1] & 255) !== 75 ||
      !(((bytes[2] & 255) === 3 && (bytes[3] & 255) === 4) ||
        ((bytes[2] & 255) === 5 && (bytes[3] & 255) === 6))) {
    throw new Error('Invalid ZIP attachment or attachment exceeds 20 MB.');
  }
  validateZip_(bytes);
  var fileName = String(data.fileName || '履歴書.zip').replace(/[\r\n/\\]/g, '_').slice(0, 180);
  return Utilities.newBlob(bytes, 'application/zip', fileName);
}

function doPost(e) {
  try {
    var data = JSON.parse(e.postData.contents);
    if (!data || typeof data !== 'object' || Array.isArray(data)) {
      throw new Error('Invalid request.');
    }

    // Retain the existing translation request contract.
    if (data.action === 'translate') {
      var text = data.text || '';
      var translated = text.trim() ? LanguageApp.translate(text, data.sourceLang || '', data.targetLang || 'ja') : '';
      return jsonResponse_({success: true, translatedText: translated});
    }

    var zipBlob = attachment_(data);
    var subjectName = String(data.fullname || '応募者').replace(/[\r\n]/g, ' ').slice(0, 120);
    var fields = [
      ['氏名 (Name)', data.fullname], ['フリガナ', data.furigana],
      ['国籍', data.nationality], ['在留資格', data.visa],
      ['電話', data.phone], ['Email', data.email]
    ];
    var attachmentNote = '※ ZIPファイルに履歴書(Word)と証明写真・在留カード・資格証明書が含まれています。';
    var body = '新しい履歴書が届きました。\n\n' + fields.map(function (field) {
      return field[0] + ': ' + String(field[1] || '-');
    }).join('\n') + '\n\n' + attachmentNote + '\n\nYourBright Co., Ltd.\n履歴書自動送信システム';
    var htmlBody = '<div style="font-family:sans-serif;max-width:600px">' +
      '<h2 style="color:#1a237e">📄 新しい履歴書が届きました</h2>' +
      '<table style="border-collapse:collapse;width:100%">' + fields.map(function (field) {
        return '<tr><td style="padding:8px;border:1px solid #ddd;background:#f5f5f5;font-weight:bold">' +
          escapeHtml_(field[0]) + '</td><td style="padding:8px;border:1px solid #ddd">' +
          escapeHtml_(field[1] || '-') + '</td></tr>';
      }).join('') + '</table><p>' + attachmentNote + '</p><hr><p>YourBright Co., Ltd. — 履歴書自動送信システム</p></div>';

    // Never trust recipients supplied by an anonymous caller.
    sendOnce_(data, function () { MailApp.sendEmail(RESUME_RECIPIENT, '【履歴書】' + subjectName, body, {
      htmlBody: htmlBody, attachments: [zipBlob], name: 'YourBright 履歴書システム'
    }); });
    return jsonResponse_({success: true, message: 'Email sent successfully to: ' + RESUME_RECIPIENT});
  } catch (error) {
    return jsonResponse_({success: false, error: String(error)});
  }
}

// Authorizes the send-only scope without sending a message.
function authorizeEmail() {
  return MailApp.getRemainingDailyQuota();
}

// Run only after approval. Uses synthetic data and sends exactly one message to staff.
function testSend() {
  var zip = Utilities.zip([Utilities.newBlob('YourBright resume email recovery check. No applicant data.', 'text/plain', 'recovery-check.txt')], 'recovery-check.zip');
  var challenge = challenge_(), proof = 0;
  while (digest_(challenge.token + ':' + proof).slice(0, 3) !== '000') proof++;
  var result = doPost({postData: {contents: JSON.stringify({
    challenge: challenge, proof: proof, fullname: 'SYSTEM RECOVERY TEST 20261015',
    zipBase64: Utilities.base64Encode(zip.getBytes()), fileName: 'recovery-check.zip'
  })}});
  Logger.log(result.getContent());
}
