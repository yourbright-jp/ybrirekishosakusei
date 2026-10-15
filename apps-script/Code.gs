// Deploy as yamashita.hayato@yourbright.co.jp. Recipient is fixed server-side.
var RESUME_RECIPIENT = 'staff@yourbright.co.jp';
var RESUME_VERSION = '2026-10-15-turnstile-v1';
var MAX_ZIP_BYTES = 20 * 1024 * 1024;
var MAX_REQUEST_CHARS = 29 * 1024 * 1024;
var TURNSTILE_HOSTNAME = 'yourbright-jp.github.io';
var TURNSTILE_ACTION = 'resume-mail';

function jsonResponse_(value) {
  return ContentService.createTextOutput(JSON.stringify(value)).setMimeType(ContentService.MimeType.JSON);
}
function doGet() {
  return jsonResponse_({success: true, service: 'yourbright-rirekisho-email', version: RESUME_VERSION,
    configured: !!PropertiesService.getScriptProperties().getProperty('TURNSTILE_SECRET')});
}
function escapeHtml_(value) {
  return String(value).replace(/[&<>"']/g, function (c) {
    return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];
  });
}
function hex_(bytes) { return bytes.map(function (b) { return ('0'+(b&255).toString(16)).slice(-2); }).join(''); }
function digest_(text) { return hex_(Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256,text,Utilities.Charset.UTF_8)); }
function equal_(a,b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  var difference=0; for(var i=0;i<a.length;i++) difference|=a.charCodeAt(i)^b.charCodeAt(i);
  return difference===0;
}
function ticketSecret_() {
  var props=PropertiesService.getScriptProperties(), secret=props.getProperty('ticket-secret');
  if (secret) return secret;
  var lock=LockService.getScriptLock(); lock.waitLock(10000);
  try {
    secret=props.getProperty('ticket-secret');
    if (!secret) { secret=Utilities.getUuid()+Utilities.getUuid(); props.setProperty('ticket-secret',secret); }
    return secret;
  } finally { lock.releaseLock(); }
}
// Verify the small browser proof before the large ZIP upload. The signed ticket
// binds an exact cached payload and allows two hours for a slow mobile upload.
function issueTicket_(data) {
  if (typeof data.submissionId !== 'string' || !/^[a-f0-9-]{36}$/.test(data.submissionId) ||
      typeof data.payloadHash !== 'string' || !/^[a-f0-9]{64}$/.test(data.payloadHash) ||
      typeof data.token !== 'string' || !data.token || data.token.length>2048) throw new Error('Invalid verification request.');
  var secret=PropertiesService.getScriptProperties().getProperty('TURNSTILE_SECRET');
  if (!secret) throw new Error('Email verification is not configured.');
  var result;
  try {
    var response=UrlFetchApp.fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify',{
      method:'post',contentType:'application/json',muteHttpExceptions:true,
      payload:JSON.stringify({secret:secret,response:data.token})
    });
    if(response.getResponseCode()!==200) throw new Error('Verification unavailable.');
    result=JSON.parse(response.getContentText());
  } catch(error) { throw new Error('Verification unavailable. Please try again.'); }
  if(result.success!==true || result.hostname!==TURNSTILE_HOSTNAME || result.action!==TURNSTILE_ACTION ||
      result.cdata!==data.submissionId+'_'+data.payloadHash) throw new Error('Verification failed. Please try again.');
  var payload=JSON.stringify({id:data.submissionId,hash:data.payloadHash,expires:Date.now()+7200000});
  return {payload:payload,signature:hex_(Utilities.computeHmacSha256Signature(payload,ticketSecret_()))};
}
function verifyTicket_(ticket) {
  var secret=PropertiesService.getScriptProperties().getProperty('ticket-secret');
  if(!secret || !ticket || typeof ticket.payload!=='string' || ticket.payload.length>300 ||
      !equal_(ticket.signature,hex_(Utilities.computeHmacSha256Signature(ticket.payload,secret)))) throw new Error('Invalid verification ticket.');
  var value=JSON.parse(ticket.payload);
  if(!/^[a-f0-9-]{36}$/.test(value.id) || !/^[a-f0-9]{64}$/.test(value.hash) ||
      !Number.isFinite(value.expires) || value.expires<Date.now() || value.expires>Date.now()+7205000) throw new Error('Verification expired. Please try again.');
  return value;
}
// Reserve the signed ID before hashing/decoding the archive. Replays return the
// existing receipt and never decode the ZIP or acquire the lock during sending.
function reserve_(ticket) {
  var props=PropertiesService.getScriptProperties(), key='submission:'+ticket.id;
  var lock=LockService.getScriptLock(); lock.waitLock(10000);
  try {
    var previous=props.getProperty(key);
    if(previous) {
      var receipt=JSON.parse(previous);
      if(receipt.hash!==ticket.hash) throw new Error('Submission already exists with different content. Contact staff.');
      if(receipt.status!=='sent') throw new Error('Delivery is unconfirmed. Contact staff before sending again.');
      return {existing:true};
    }
    var now=Date.now(), all=props.getProperties(), hourly=0, daily=0;
    Object.keys(all).forEach(function(name) {
      if(name.indexOf('submission:')!==0) return;
      var row=JSON.parse(all[name]);
      if(now-row.time>7*86400000) { props.deleteProperty(name); return; }
      if(now-row.time<86400000) daily++;
      if(now-row.time<3600000) hourly++;
    });
    if(hourly>=30 || daily>=100 || MailApp.getRemainingDailyQuota()<250) throw new Error('Email limit reached. Download the ZIP and contact staff.');
    var record={hash:ticket.hash,time:now,status:'pending'};
    props.setProperty(key,JSON.stringify(record));
    return {key:key,record:record};
  } finally { lock.releaseLock(); }
}
function finish_(reservation,status) {
  reservation.record.status=status;
  PropertiesService.getScriptProperties().setProperty(reservation.key,JSON.stringify(reservation.record));
}

// Check the central directory and every referenced local entry without inflating
// untrusted compressed bytes. The frontend uses JSZip default STORE; reject
// top-level compression so declared-size lies cannot hide an expansion bomb.
function crc32_(bytes,start,end) {
  var table=crc32_.table;
  if(!table){
    table=[];
    for(var n=0;n<256;n++){
      var c=n;
      for(var k=0;k<8;k++)c=(c&1)?(0xedb88320^(c>>>1)):(c>>>1);
      table[n]=c>>>0;
    }
    crc32_.table=table;
  }
  var crc=0xffffffff;
  for(var i=start;i<end;i++)crc=table[(crc^(bytes[i]&255))&255]^(crc>>>8);
  return (crc^0xffffffff)>>>0;
}

function validateZip_(bytes) {
  function u16(i) { return (bytes[i] & 255) + (bytes[i + 1] & 255) * 256; }
  function u32(i) { return u16(i) + u16(i + 2) * 65536; }
  function fail() { throw new Error('Invalid ZIP structure.'); }
  var end = -1;
  for (var i = bytes.length - 22; i >= Math.max(0, bytes.length - 65557); i--) {
    if (u32(i) === 0x06054b50 && i + 22 + u16(i + 20) === bytes.length) { end = i; break; }
  }
  if (end < 0 || u16(end + 4) || u16(end + 6) || u16(end + 8) !== u16(end + 10)) fail();
  var count = u16(end + 10), size = u32(end + 12), start = u32(end + 16), pos = start, expanded = 0, resumeDocuments = 0;
  if (count > 100 || start + size !== end) fail();
  for (var n = 0; n < count; n++) {
    if (pos + 46 > end || u32(pos) !== 0x02014b50 || u16(pos + 34) || (u16(pos + 8) & 1)) fail();
    var nameLength = u16(pos + 28), entryEnd = pos + 46 + nameLength + u16(pos + 30) + u16(pos + 32);
    var local = u32(pos + 42), compressed = u32(pos + 20), uncompressed = u32(pos + 24), method = u16(pos + 10);
    expanded += uncompressed;
    if (expanded > 100 * 1024 * 1024 || uncompressed > Math.max(1, compressed) * 200 ||
        method !== 0 || (method === 0 && compressed !== uncompressed)) fail();
    if (entryEnd > end || local + 30 > start || u32(local) !== 0x04034b50 || u16(local + 26) !== nameLength ||
        local + 30 + nameLength + u16(local + 28) + compressed > start ||
        u16(local + 8) !== method || u16(local + 6) !== u16(pos + 8) ||
        (!(u16(pos + 8) & 8) && (u32(local + 18) !== compressed || u32(local + 22) !== uncompressed || u32(local + 14) !== u32(pos + 16)))) fail();
    var dataStart=local+30+nameLength+u16(local+28);
    if(crc32_(bytes,dataStart,dataStart+compressed)!==u32(pos+16)) fail();
    if (!nameLength || nameLength > 4096) fail();
    var entryName = Utilities.newBlob(bytes.slice(pos + 46, pos + 46 + nameLength)).getDataAsString('UTF-8');
    function checkExtras(offset, length) {
      var finish = offset + length;
      while (offset < finish) {
        if (offset + 4 > finish) fail();
        var type = u16(offset), fieldLength = u16(offset + 2), value = offset + 4;
        if (value + fieldLength > finish) fail();
        if (type === 0x7075) {
          if (fieldLength < 5 || (bytes[value] & 255) !== 1 ||
              Utilities.newBlob(bytes.slice(value + 5, value + fieldLength)).getDataAsString('UTF-8') !== entryName) fail();
        } else if (type !== 0x5455) fail(); // Only Unicode-path and timestamp metadata are used.
        offset = value + fieldLength;
      }
    }
    checkExtras(pos + 46 + nameLength, u16(pos + 30));
    checkExtras(local + 30 + nameLength, u16(local + 28));
    var pathParts = entryName.split('/');
    if (entryName.charAt(0) === '/' || /[\\:\x00]/.test(entryName) ||
        pathParts.some(function (part, index) { return part === '.' || part === '..' || (!part && index < pathParts.length - 1); })) fail();
    if (/^履歴書_[^/]+\.docx$/i.test(entryName)) resumeDocuments++;
    else if (!/^写真_[^/]+\/$/.test(entryName) &&
        !/^写真_[^/]+\/[^/]+\.(jpg|jpeg|png|webp|gif|bmp|heic|heif|avif|tif|tiff|pdf|doc|docx)$/i.test(entryName)) fail();
    var mode = (u32(pos + 38) >>> 16) & 0xf000;
    if ((mode && mode !== 0x8000 && mode !== 0x4000) || (u32(pos + 38) & 0x400)) fail();
    for (var j = 0; j < nameLength; j++) if (bytes[local + 30 + j] !== bytes[pos + 46 + j]) fail();
    pos = entryEnd;
  }
  if (pos !== end || resumeDocuments !== 1) fail();
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
  var fileName = String(data.fileName || '履歴書.zip').replace(/[<>:\x00-\x20/\\|?*]/g, '_').replace(/\.zip$/i, '').slice(0, 174) + '.zip';
  return Utilities.newBlob(bytes, 'application/zip', fileName);
}

function sendMail_(data,zipBlob) {
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
}

function doPost(e) {
  var reservation,mailStarted=false;
  try {
    if(!e || !e.postData || typeof e.postData.contents!=='string' || e.postData.contents.length>MAX_REQUEST_CHARS) throw new Error('Invalid request size.');
    var request=JSON.parse(e.postData.contents);
    if(!request || typeof request!=='object' || Array.isArray(request)) throw new Error('Invalid request.');
    if(request.action==='verify') {
      if(e.postData.contents.length>8192) throw new Error('Invalid verification request size.');
      return jsonResponse_({success:true,ticket:issueTicket_(request)});
    }
    if(request.action) throw new Error('Unsupported action.');
    var ticket=verifyTicket_(request.ticket);
    if(typeof request.payload!=='string' || request.payload.length>MAX_REQUEST_CHARS) throw new Error('Invalid payload.');
    reservation=reserve_(ticket);
    if(reservation.existing) return jsonResponse_({success:true,reused:true});
    if(!equal_(digest_(request.payload),ticket.hash)) throw new Error('Payload does not match verification.');
    var data=JSON.parse(request.payload);
    if(!data || typeof data!=='object' || Array.isArray(data)) throw new Error('Invalid payload.');
    ['fullname','furigana','nationality','visa','phone','email','fileName'].forEach(function(field) {
      if(data[field]!==undefined && (typeof data[field]!=='string' || data[field].length>500)) throw new Error('Invalid applicant field.');
    });
    var zipBlob=attachment_(data);
    mailStarted=true;
    sendMail_(data,zipBlob);
    finish_(reservation,'sent');
    return jsonResponse_({success:true,message:'Email sent successfully to: '+RESUME_RECIPIENT});
  } catch(error) {
    if(reservation && !reservation.existing && !mailStarted) finish_(reservation,'rejected');
    return jsonResponse_({success:false,error:String(error)});
  }
}
function authorizeEmail() { return MailApp.getRemainingDailyQuota(); }
