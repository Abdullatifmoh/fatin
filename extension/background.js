'use strict';
const recent=new Map();
function publicUrl(raw){try{const u=new URL(raw);if(!['https:','http:'].includes(u.protocol)||['localhost','127.0.0.1','[::1]'].includes(u.hostname))return null;u.username='';u.password='';u.search='';u.hash='';u.pathname='/';return u.href;}catch{return null}}
async function notify(tabId,msg){try{await chrome.tabs.sendMessage(tabId,msg)}catch{/* Existing pages need one reload after install. */}}
chrome.tabs.onUpdated.addListener(async(id,info)=>{if(info.status==='complete'){const s=await chrome.storage.local.get('enabled');await notify(id,{type:'fatin-status',enabled:!!s.enabled});}});
chrome.tabs.onActivated.addListener(async({tabId})=>{const s=await chrome.storage.local.get('enabled');await notify(tabId,{type:'fatin-status',enabled:!!s.enabled});});
chrome.tabs.onRemoved.addListener(id=>recent.delete(id));
async function broadcast(){const s=await chrome.storage.local.get('enabled');const tabs=await chrome.tabs.query({});for(const t of tabs){await notify(t.id,{type:'fatin-status',enabled:!!s.enabled});if(!s.enabled){await notify(t.id,{type:'fatin-clear'});await chrome.action.setBadgeText({tabId:t.id,text:''});}}recent.clear();if(s.enabled){const [t]=await chrome.tabs.query({active:true,currentWindow:true});if(t)await notify(t.id,{type:'fatin-status',enabled:true});}}
chrome.storage.onChanged.addListener((changes,area)=>{if(area==='local'&&(changes.enabled||changes.server))broadcast()});
chrome.runtime.onMessage.addListener((msg,sender,reply)=>{(async()=>{const s=await chrome.storage.local.get(['enabled','server','dashboard']);
if(msg.type==='scan-page'){
 if(!s.enabled||!s.server){reply({error:'الحماية متوقفة أو الخادم غير محدد'});return;}
 const url=publicUrl(sender.url);if(!url||!sender.tab){reply({error:'صفحة غير مدعومة'});return;}
 const snapshot=msg.snapshot||{};
 const body={url,title:typeof snapshot.title==='string'?snapshot.title.slice(0,300):'',headings:typeof snapshot.headings==='string'?snapshot.headings.slice(0,600):'',password:snapshot.password===true,payment:snapshot.payment===true,ai_consent:true};
 try{const {token}=await chrome.storage.session.get('token');const r=await fetch(s.server+'/api/browser-check',{method:'POST',headers:{'Content-Type':'application/json',...(token?{Authorization:'Bearer '+token}:{})},body:JSON.stringify(body),signal:AbortSignal.timeout(38000)});const d=await r.json();if(!r.ok)throw Error();await chrome.action.setBadgeText({tabId:sender.tab.id,text:d.risk==='high'?'!':d.risk==='medium'?'?':'·'});await chrome.storage.local.set({lastStatus:{time:new Date().toISOString(),risk:d.risk,engine:d.engine,notice:d.notice}});reply({result:d});}catch{reply({error:'تعذر شرح الخادم؛ المقارنة المحلية مستمرة.'});}return;
}
if(msg.type==='get-status'){reply({enabled:!!s.enabled});return;}
if(msg.type==='open-dashboard'){if(s.dashboard)await chrome.tabs.create({url:s.dashboard});reply({ok:true});return;}
if(msg.type==='set-protection'){// Only the configured dashboard may control the extension through a web bridge.
let trusted=false;try{const actual=new URL(sender.url), expected=new URL(s.dashboard);trusted=actual.origin===expected.origin&&actual.pathname.replace(/\/$/,'')===expected.pathname.replace(/\/$/,'');}catch{}
if(!trusted){reply({error:'هذه الصفحة ليست لوحة فطن المحددة في الإضافة.'});return;}
if(msg.enabled){const granted=await chrome.permissions.contains({origins:['http://*/*','https://*/*']});if(!granted||!s.server){reply({error:'افتح نافذة الإضافة لتحديد الخادم ومنح إذن الحماية أولًا.'});return;}}
await chrome.storage.local.set({enabled:!!msg.enabled});reply({enabled:!!msg.enabled});return;}
reply({error:'طلب غير مدعوم'});
})().catch(()=>reply({error:'تعذر تنفيذ الطلب'}));return true;});
