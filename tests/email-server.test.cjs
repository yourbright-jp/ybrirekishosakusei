const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm'),crypto=require('node:crypto');
const {test}=require('node:test');
const source=fs.readFileSync(path.resolve(__dirname,'../apps-script/Code.gs'),'utf8');
function zip(entries=[{name:'履歴書_TEST.docx'}]){
  const locals=[],centrals=[];let offset=0;
  for(const entry of entries){
    const name=Buffer.from(entry.name),body=Buffer.from(entry.body||'synthetic test fixture'),method=entry.method||0;
    let extra=Buffer.alloc(0);
    if(entry.unicode){const unicode=Buffer.from(entry.unicode);extra=Buffer.alloc(9+unicode.length);extra.writeUInt16LE(0x7075);extra.writeUInt16LE(5+unicode.length,2);extra[4]=1;unicode.copy(extra,9);}
    const local=Buffer.alloc(30),central=Buffer.alloc(46);
    local.writeUInt32LE(0x04034b50);local.writeUInt16LE(method,8);local.writeUInt32LE(body.length,18);local.writeUInt32LE(body.length,22);local.writeUInt16LE(name.length,26);local.writeUInt16LE(extra.length,28);
    central.writeUInt32LE(0x02014b50);central.writeUInt16LE(method,10);central.writeUInt32LE(body.length,20);central.writeUInt32LE(body.length,24);central.writeUInt16LE(name.length,28);central.writeUInt16LE(extra.length,30);central.writeUInt32LE(offset,42);
    if(entry.mode)central.writeUInt32LE(entry.mode*65536,38);
    const bytes=Buffer.concat([local,name,extra,body]);locals.push(bytes);centrals.push(central,name,extra);offset+=bytes.length;
  }
  const directory=Buffer.concat(centrals),end=Buffer.alloc(22);end.writeUInt32LE(0x06054b50);end.writeUInt16LE(entries.length,8);end.writeUInt16LE(entries.length,10);end.writeUInt32LE(directory.length,12);end.writeUInt32LE(offset,16);
  return Buffer.concat([...locals,directory,end]);
}
function request(extra={}){return {fullname:'Recovery fixture',zipBase64:zip().toString('base64'),fileName:'履歴書.zip',...extra};}
function server(options={}){
  const sent=[],properties=new Map([['TURNSTILE_SECRET','synthetic-secret']]);let decoded=0,fetched=0,lastVerification,locked=false;
  const props={getProperty:k=>properties.get(k)||null,setProperty:(k,v)=>properties.set(k,v),deleteProperty:k=>properties.delete(k),getProperties:()=>Object.fromEntries(properties)};
  const context=vm.createContext({
    ContentService:{MimeType:{JSON:'application/json'},createTextOutput:text=>({setMimeType(){return this;},getContent(){return text;}})},
    PropertiesService:{getScriptProperties:()=>props},
    LockService:{getScriptLock:()=>({waitLock(){assert.equal(locked,false);locked=true;},releaseLock(){locked=false;}})},
    Utilities:{DigestAlgorithm:{SHA_256:'sha256'},Charset:{UTF_8:'utf8'},getUuid:()=>crypto.randomUUID(),
      computeDigest:(alg,value)=>[...crypto.createHash(alg).update(value).digest()],
      computeHmacSha256Signature:(value,key)=>[...crypto.createHmac('sha256',key).update(value).digest()],
      base64Decode:value=>{decoded++;return options.decodedBytes||[...Buffer.from(value,'base64')];},
      newBlob:(bytes,mime,name)=>({bytes,mime,name,getDataAsString:()=>Buffer.from(bytes).toString('utf8')})},
    UrlFetchApp:{fetch:(url,opts)=>{fetched++;assert.equal(url,'https://challenges.cloudflare.com/turnstile/v0/siteverify');const input=JSON.parse(opts.payload);assert.equal(input.secret,'synthetic-secret');return {getResponseCode:()=>options.status||200,getContentText:()=>JSON.stringify({success:true,hostname:'yourbright-jp.github.io',action:'resume-mail',cdata:lastVerification.submissionId+'_'+lastVerification.payloadHash,...options.verification})};}},
    MailApp:{getRemainingDailyQuota:()=>options.quota??1000,sendEmail:(...args)=>{assert.equal(locked,false,'mail provider must run outside the global lock');if(options.sendError)throw new Error(options.sendError);sent.push(args);}}
  });vm.runInContext(source,context);
  const post=data=>JSON.parse(context.doPost({postData:{contents:JSON.stringify(data)}}).getContent());
  function signed(extra={},id=crypto.randomUUID()){
    const payload=JSON.stringify(request(extra));lastVerification={action:'verify',submissionId:id,payloadHash:crypto.createHash('sha256').update(payload).digest('hex'),token:'synthetic-token'};
    const proof=post(lastVerification);return {ticket:proof.ticket,payload};
  }
  return {context,sent,properties,post,signed,get decoded(){return decoded;},get fetched(){return fetched;},verify(data){lastVerification=data;return post(data);}};
}
test('health and scope authorization send no email',()=>{
  const app=server();assert.equal(JSON.parse(app.context.doGet().getContent()).configured,true);assert.equal(app.context.authorizeEmail(),1000);assert.equal(app.sent.length,0);
});
test('successful proof binds exact payload; only staff receives the message',()=>{
  const app=server(),data=app.signed({emails:['attacker@example.org']});assert.ok(data.ticket);assert.equal(app.post(data).success,true);assert.equal(app.sent.length,1);assert.equal(app.sent[0][0],'staff@yourbright.co.jp');assert.deepEqual(Buffer.from(app.sent[0][3].attachments[0].bytes),zip());
});
test('invalid token, hostname, action or cdata cannot issue a ticket',()=>{
  for(const verification of [{success:false},{hostname:'evil.example'},{action:'other'},{cdata:'other'}]){
    const app=server({verification});assert.equal(app.signed().ticket,undefined);assert.equal(app.decoded,0);assert.equal(app.sent.length,0);
  }
  const app=server();assert.equal(app.verify({action:'verify',submissionId:crypto.randomUUID(),payloadHash:'a'.repeat(64),token:'x'.repeat(2049)}).success,false);assert.equal(app.fetched,0);
});
test('unsigned, forged and expired tickets reject before decoding',()=>{
  const app=server(),data=app.signed();
  for(const item of [request(),{...data,ticket:{...data.ticket,signature:'0'.repeat(64)}}])assert.equal(app.post(item).success,false);
  const value=JSON.parse(data.ticket.payload);value.expires=Date.now()-1000;data.ticket.payload=JSON.stringify(value);data.ticket.signature=crypto.createHmac('sha256',app.properties.get('ticket-secret')).update(data.ticket.payload).digest('hex');
  assert.equal(app.post(data).success,false);assert.equal(app.decoded,0);assert.equal(app.sent.length,0);
});
test('ticket allows a slow upload within two hours',()=>{
  const app=server(),data=app.signed(),value=JSON.parse(data.ticket.payload);value.expires=Date.now()+30*60000;data.ticket.payload=JSON.stringify(value);data.ticket.signature=crypto.createHmac('sha256',app.properties.get('ticket-secret')).update(data.ticket.payload).digest('hex');assert.equal(app.post(data).success,true);
});
test('replays return the receipt without hashing or decoding the ZIP again',()=>{
  const app=server(),data=app.signed();assert.equal(app.post(data).success,true);const decoded=app.decoded;
  app.context.Utilities.computeDigest=()=>{throw new Error('Replay must not hash');};
  assert.equal(app.post(data).success,true);assert.equal(app.decoded,decoded);assert.equal(app.sent.length,1);
});
test('new token for the same ID cannot send a second message or alter accepted data',()=>{
  const app=server(),id=crypto.randomUUID(),first=app.signed({},id);assert.equal(app.post(first).success,true);assert.equal(app.post(app.signed({},id)).success,true);assert.equal(app.post(app.signed({fullname:'Changed'},id)).success,false);assert.equal(app.sent.length,1);
});
test('hash mismatch and provider uncertainty never permit a retry send',()=>{
  const app=server(),data=app.signed();assert.equal(app.post({...data,payload:data.payload+' '}).success,false);assert.equal(app.post(data).success,false);assert.equal(app.decoded,0);
  const failed=server({sendError:'ambiguous provider failure'}),pending=failed.signed();assert.equal(failed.post(pending).success,false);assert.match(failed.post(pending).error,/unconfirmed/);assert.equal(failed.decoded,1);assert.equal(failed.sent.length,0);
});
test('budgets and remaining sender quota reject before ZIP decoding',()=>{
  for(const [count,age] of [[30,1000],[100,7200000]]){
    const app=server();for(let i=0;i<count;i++)app.properties.set('submission:fixture'+i,JSON.stringify({time:Date.now()-age}));assert.equal(app.post(app.signed()).success,false);assert.equal(app.decoded,0);
  }
  const app=server({quota:249});assert.equal(app.post(app.signed()).success,false);assert.equal(app.decoded,0);
});
test('mail HTML and headers cannot be injected by applicant fields',()=>{
  const app=server();assert.equal(app.post(app.signed({fullname:'<img src=x>\r\nBcc: attacker@example.org',phone:'<script>x</script>',fileName:'../resume\n.zip'})).success,true);
  const mail=app.sent[0];assert.doesNotMatch(mail[1],/[\r\n]/);assert.doesNotMatch(mail[3].htmlBody,/<img|<script>/);assert.match(mail[3].htmlBody,/&lt;img/);assert.doesNotMatch(mail[3].attachments[0].name,/[\r\n/\\]/);
});
test('encoded/decoded limits and malformed archive fail without a mail',()=>{
  for(const zipBase64 of ['!!!!','dGVzdA==','A'.repeat(Math.ceil(20*1024*1024/3)*4+4),Buffer.from('504b0304','hex').toString('base64')]){const app=server();assert.equal(app.post(app.signed({zipBase64})).success,false);assert.equal(app.sent.length,0);}
  const app=server({decodedBytes:{length:20*1024*1024+1}});assert.equal(app.post(app.signed()).success,false);assert.equal(app.sent.length,0);
});
test('only one generated resume plus supported document/image attachments are accepted',()=>{
  for(const extension of ['jpg','png','pdf','doc','docx','heic']){const app=server();assert.equal(app.post(app.signed({zipBase64:zip([{name:'履歴書_TEST.docx'},{name:'写真_TEST/'},{name:'写真_TEST/資格証.'+extension}]).toString('base64')})).success,true,extension);}
  for(const entries of [[],[{name:'test.html'}],[{name:'履歴書_A.docx'},{name:'履歴書_B.docx'}],[{name:'履歴書_TEST.docx'},{name:'写真_TEST/link.url'}],[{name:'履歴書_TEST.docx'},{name:'写真_TEST/image.svg'}]]){const app=server();assert.equal(app.post(app.signed({zipBase64:zip(entries).toString('base64')})).success,false);assert.equal(app.sent.length,0);}
});
test('traversal, symlinks, compression and alternate Unicode names are rejected',()=>{
  for(const entry of [{name:'../履歴書_TEST.docx'},{name:'/履歴書_TEST.docx'},{name:'C:履歴書_TEST.docx'},{name:'履歴書_TEST.docx',mode:0xa000},{name:'履歴書_TEST.docx',method:8},{name:'履歴書_TEST.docx',unicode:'../escape.docx'}]){const app=server();assert.equal(app.post(app.signed({zipBase64:zip([entry]).toString('base64')})).success,false);assert.equal(app.sent.length,0);}
  const app=server();assert.equal(app.post(app.signed({zipBase64:zip([{name:'履歴書_TEST.docx',unicode:'履歴書_TEST.docx'}]).toString('base64')})).success,true);
});
test('unsupported actions, malformed JSON and oversized verification fail closed',()=>{
  const app=server();for(const data of [null,[],{}, {action:'translate'}, {action:'verify',padding:'x'.repeat(8192)}])assert.equal(app.post(data).success,false);
  assert.equal(JSON.parse(app.context.doPost({postData:{contents:'{'}}).getContent()).success,false);assert.equal(app.sent.length,0);
});
