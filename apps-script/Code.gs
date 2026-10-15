// YourBright resume email server. Deploy as yamashita.hayato@yourbright.co.jp.
// Only the send-mail scope is required; the script cannot read the Gmail inbox.
var RESUME_RECIPIENT = 'staff@yourbright.co.jp';
var RESUME_VERSION = '2026-10-15';
var MAX_ZIP_BYTES = 20 * 1024 * 1024;

function jsonResponse_(value) {
  return ContentService.createTextOutput(JSON.stringify(value))
    .setMimeType(ContentService.MimeType.JSON);
}

function doGet() {
  return jsonResponse_({success: true, service: 'yourbright-rirekisho-email', version: RESUME_VERSION});
}

function escapeHtml_(value) {
  return String(value).replace(/[&<>"']/g, function (character) {
    return {'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[character];
  });
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
    MailApp.sendEmail(RESUME_RECIPIENT, '【履歴書】' + subjectName, body, {
      htmlBody: htmlBody, attachments: [zipBlob], name: 'YourBright 履歴書システム'
    });
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
  var result = doPost({postData: {contents: JSON.stringify({
    fullname: 'SYSTEM RECOVERY TEST 20261015',
    zipBase64: Utilities.base64Encode(zip.getBytes()), fileName: 'recovery-check.zip'
  })}});
  Logger.log(result.getContent());
}
