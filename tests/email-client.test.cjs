const {test}=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm'),crypto=require('node:crypto');
const html=fs.readFileSync(require('node:path').join(__dirname,'../index.html'),'utf8');
for(const script of html.matchAll(/<script(?:\s[^>]*)?>([\s\S]*?)<\/script>/g))new vm.Script(script[1]);
const code=html.slice(html.indexOf('const APPS_SCRIPT_URL='),html.indexOf('function showSuccess()'));
function client(mode){
  const calls=[],alerts=[],bindings=[];let success=0,downloads=0,generated=0;
  const context=vm.createContext({TextEncoder,Uint8Array,Blob,Date,JSON,crypto:crypto.webcrypto,atob,
    sessionStorage:{getItem(){return null;},setItem(){}},
    JSZip:class{file(){}folder(){return this;}async generateAsync(){generated++;return Buffer.from('ZIP fixture '+generated).toString('base64');}},
    data:{fullname:'SYSTEM TEST'},photoData:null,zairyuFront:[],zairyuBack:[],certFiles:{},getSelectedEmails:()=>['staff@yourbright.co.jp'],t:()=>'',showLoading(){},hideLoading(){},alert:message=>alerts.push(message),console:{error(){}},generateWord:async()=>new Blob(['synthetic']),mobileSave(){downloads++;},showSuccess(){success++;},
    fetch:async(url,options)=>{
      calls.push({url,body:JSON.parse(options.body)});
      if(JSON.parse(options.body).action==='verify')return {ok:true,json:async()=>({success:mode!=='verify-failure',ticket:{payload:'fixture',signature:'fixture'}})};
      if(mode==='network')throw new Error('Lost response');
      return {ok:true,json:async()=>{if(mode==='invalid-json')throw new Error('Not JSON');return {success:mode==='success'};}};
    }
  });vm.runInContext(code,context);
  context.requestEmailVerification=async binding=>{bindings.push(binding);return 'fixture-token';};
  return {run:()=>context.doEmailZip(),context,calls,alerts,bindings,get success(){return success;},get downloads(){return downloads;},get generated(){return generated;}};
}
test('confirmed response verifies the exact payload before one send and shows success',async()=>{
  const app=client('success');await app.run();assert.equal(app.calls.length,2);assert.equal(app.calls[0].body.action,'verify');assert.equal(app.calls[0].body.payloadHash,crypto.createHash('sha256').update(app.calls[1].body.payload).digest('hex'));assert.equal(app.bindings[0],app.calls[0].body.submissionId+'_'+app.calls[0].body.payloadHash);assert.equal(app.success,1);assert.equal(app.downloads,1);
});
test('lost, invalid and failed responses never retry automatically or show completion',async()=>{
  for(const mode of ['network','invalid-json','failure']){const app=client(mode);await app.run();assert.equal(app.calls.length,2);assert.equal(app.success,0);assert.equal(app.downloads,1);}
});
test('failed verification does not upload the large payload',async()=>{
  const app=client('verify-failure');await app.run();assert.equal(app.calls.length,1);assert.equal(app.success,0);assert.equal(app.downloads,1);
});
test('double click creates only one archive and one send',async()=>{
  const app=client('success');await Promise.all([app.run(),app.run()]);assert.equal(app.calls.length,2);assert.equal(app.generated,1);
});
test('manual retry keeps exact timestamped archive, hash and submission ID after lost response',async()=>{
  const app=client('network');await app.run();await app.run();assert.equal(app.generated,1);assert.equal(app.calls[0].body.submissionId,app.calls[2].body.submissionId);assert.equal(app.calls[0].body.payloadHash,app.calls[2].body.payloadHash);assert.equal(app.calls[1].body.payload,app.calls[3].body.payload);assert.equal(app.success,0);
});
test('editing clears cached bytes while restart clears the identity too',()=>{
  assert.match(html,/function backToEdit\(\)\{emailPayloadCache=null;/);assert.match(html,/function restart\(\)\{emailPayloadCache=null;emailSubmissionId=null;/);assert.doesNotMatch(code,/no-cors|action=challenge|proof<=/);
});
