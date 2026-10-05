const vm=require('node:vm'),fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict');
const {inspectIdentity}=require('../extension/identity.js');
const handlers={},sent=[],calls=[];let store={enabled:true,server:'https://fatin.onrender.com',dashboard:'https://abdullatifmoh.github.io/fatin/'},tab={id:1,url:'https://spl.example.test/?token=SECRET'};
const event=name=>({addListener:fn=>handlers[name]=fn});
const chrome={storage:{local:{get:async()=>({...store}),set:async x=>Object.assign(store,x)},session:{get:async()=>({token:''})},onChanged:event('changed')},tabs:{sendMessage:async(id,m)=>sent.push(m),query:async()=>[tab],create:async()=>{},onUpdated:event('updated'),onActivated:event('activated'),onRemoved:event('removed')},action:{setBadgeText:async()=>{}},permissions:{contains:async()=>true},runtime:{onMessage:event('message')}};
const ctx=vm.createContext({chrome,URL,Map,Date,AbortSignal,setTimeout,clearTimeout,fetch:async(url,opts)=>{const body=JSON.parse(opts.body);calls.push(body);return {ok:true,json:async()=>inspectIdentity(body)}}});
vm.runInContext(fs.readFileSync(path.join(__dirname,'../extension/background.js'),'utf8'),ctx);
function message(m,sender){return new Promise(resolve=>handlers.message(m,sender,resolve));}
(async()=>{
 const d=await message({type:'scan-page',snapshot:{url:'https://evil.test',title:'البريد السعودي',payment:true,values:{card:'SECRET'}}},{url:tab.url,tab});
 assert.equal(d.result.risk,'high');assert(!JSON.stringify(calls).includes('SECRET'));assert.equal(calls[0].url,'https://spl.example.test/');
 assert((await message({type:'set-protection',enabled:false},{url:'https://evil.example/'})).error);
 await message({type:'set-protection',enabled:false},{url:store.dashboard});assert.equal(store.enabled,false);
 const n=calls.length;assert((await message({type:'scan-page',snapshot:{}},{url:tab.url,tab})).error);assert.equal(calls.length,n);
 console.log('PASS: extension sender URL, secret exclusion, trusted dashboard and disabled protection');
})().catch(e=>{console.error(e);process.exit(1)});
