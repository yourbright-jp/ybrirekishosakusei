const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const vm=require('node:vm');
const crypto=require('node:crypto');
const html=fs.readFileSync(require('node:path').join(__dirname,'../index.html'),'utf8');
for(const script of html.matchAll(/<script(?:\s[^>]*)?>([\s\S]*?)<\/script>/g))new vm.Script(script[1]);
const code=html.slice(html.indexOf('const APPS_SCRIPT_URL='),html.indexOf('function showSuccess()'));
function client(mode){
  const calls=[],alerts=[];let success=0,downloads=0;
  const context=vm.createContext({
    TextEncoder,Uint8Array,Blob,Date,JSON,crypto:crypto.webcrypto,atob,
    sessionStorage:{getItem(){return null;},setItem(){}},
    JSZip:class {file(){}folder(){return this;}async generateAsync(){return 'UEsFBgAAAAAAAAAAAAAAAAAAAAAAAA==';}},
    data:{fullname:'SYSTEM TEST'},photoData:null,zairyuFront:[],zairyuBack:[],certFiles:{},
    getSelectedEmails:()=>['staff@yourbright.co.jp'],t:()=>'',showLoading(){},hideLoading(){},
    alert:message=>alerts.push(message),console:{error(){}},
    generateWord:async()=>new Blob(['synthetic']),mobileSave(){downloads++;},showSuccess(){success++;},
    fetch:async(url,options)=>{
      calls.push({url,options});
      if(!options)return {ok:true,json:async()=>({success:true,challenge:{token:'fixture'}})};
      if(mode==='network')throw new Error('Lost response');
      return {ok:true,json:async()=>{if(mode==='invalid-json')throw new Error('Not JSON');return {success:mode==='success'};}};
    }
  });
  vm.runInContext(code,context);
  return {run:()=>context.doEmailZip(),calls,alerts,get success(){return success;},get downloads(){return downloads;}};
}
test('a confirmed response sends one POST and shows success',async()=>{
  const app=client('success');await app.run();
  assert.equal(app.calls.filter(c=>c.options).length,1);
  assert.equal(app.success,1);assert.equal(app.downloads,1);
});
test('lost, invalid and failed responses never retry or show completion',async()=>{
  for(const mode of ['network','invalid-json','failure']){
    const app=client(mode);await app.run();
    assert.equal(app.calls.filter(c=>c.options).length,1);
    assert.equal(app.success,0);assert.equal(app.downloads,1);
  }
});
test('double clicking while sending still produces only one POST',async()=>{
  const app=client('success');await Promise.all([app.run(),app.run()]);
  assert.equal(app.calls.filter(c=>c.options).length,1);
});

test('manual retry keeps the submission ID even when a response was lost',async()=>{
  const app=client('network');await app.run();await app.run();
  const challenges=app.calls.filter(c=>!c.options).map(c=>c.url);
  assert.equal(challenges.length,2);assert.equal(challenges[0],challenges[1]);
});
