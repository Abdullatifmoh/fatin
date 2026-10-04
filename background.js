'use strict';
const recent=new Map();
function publicUrl(raw){try{const u=new URL(raw);if(!['https:','http:'].includes(u.protocol)||['localhost','127.0.0.1','[::1]'].includes(u.hostname))return null;u.username='';u.password='';u.search='';u.hash='';return u.href;}catch{return null}}
async function notify(tabId,msg){try{await chrome.tabs.sendMessage(tabId,msg)}catch{/* Existing pages need one reload after install. */}}
async function check(tabId,raw){const s=await chrome.storage.local.get(['enabled','server','dashboard']);if(!s.enabled||!s.server)return;const url=publicUrl(raw);if(!url)return;try{if(new URL(url).origin===new URL(s.server).origin)return;}catch{return;}
const now=Date.now(), prev=recent.get(tabId);if(prev?.url===url&&now-prev.at<60000)return;const record={url,at:now};recent.set(tabId,record);const {token}=await chrome.storage.session.get('token');const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),40000);
try{const r=await fetch(s.server+'/api/browser-check',{method:'POST',headers:{'Content-Type':'application/json',...(token?{Authorization:'Bearer '+token}:{})},body:JSON.stringify({url,ai_consent:true}),signal:controller.signal});const d=await r.json();const current=await chrome.tabs.get(tabId), settings=await chrome.storage.local.get('enabled');if(!settings.enabled||publicUrl(current.url)!==url||recent.get(tabId)!==record)return;if(!r.ok)throw Error(d.error||'تعذر الفحص');await chrome.action.setBadgeText({tabId,text:d.risk==='high'?'!':d.risk==='medium'?'?':'·'});await chrome.action.setBadgeBackgroundColor({tabId,color:d.risk==='high'?'#bd3a51':'#6340ad'});await chrome.storage.local.set({lastStatus:{time:new Date().toISOString(),risk:d.risk,notice:d.notice||'',engine:d.engine}});if(['high','medium'].includes(d.risk))await notify(tabId,{type:'fatin-result',result:d});else await notify(tabId,{type:'fatin-clear'});
}catch(e){recent.delete(tabId);await chrome.action.setBadgeText({tabId,text:'×'});await chrome.storage.local.set({lastStatus:{time:new Date().toISOString(),error:'تعذر فحص الموقع. تحقق من اتصال الخادم؛ الحماية غير مكتملة.'}});}finally{clearTimeout(timer)}}
chrome.tabs.onUpdated.addListener((id,info,tab)=>{if(info.status==='complete'&&tab.active)check(id,tab.url)});
chrome.tabs.onActivated.addListener(async({tabId})=>{try{const t=await chrome.tabs.get(tabId);check(tabId,t.url)}catch{}});
chrome.tabs.onRemoved.addListener(id=>recent.delete(id));
async function broadcast(){const s=await chrome.storage.local.get('enabled');const tabs=await chrome.tabs.query({});for(const t of tabs){await notify(t.id,{type:'fatin-status',enabled:!!s.enabled});if(!s.enabled){await notify(t.id,{type:'fatin-clear'});await chrome.action.setBadgeText({tabId:t.id,text:''});}}recent.clear();if(s.enabled){const [t]=await chrome.tabs.query({active:true,currentWindow:true});if(t)check(t.id,t.url);}}
chrome.storage.onChanged.addListener((changes,area)=>{if(area==='local'&&(changes.enabled||changes.server))broadcast()});
chrome.runtime.onMessage.addListener((msg,sender,reply)=>{(async()=>{const s=await chrome.storage.local.get(['enabled','server','dashboard']);
if(msg.type==='get-status'){reply({enabled:!!s.enabled});return;}
if(msg.type==='open-dashboard'){if(s.dashboard)await chrome.tabs.create({url:s.dashboard});reply({ok:true});return;}
if(msg.type==='set-protection'){// Only the configured dashboard may control the extension through a web bridge.
let trusted=false;try{const actual=new URL(sender.url), expected=new URL(s.dashboard);trusted=actual.origin===expected.origin&&actual.pathname.replace(/\/$/,'')===expected.pathname.replace(/\/$/,'');}catch{}
if(!trusted){reply({error:'هذه الصفحة ليست لوحة فطن المحددة في الإضافة.'});return;}
if(msg.enabled){const granted=await chrome.permissions.contains({origins:['http://*/*','https://*/*']});if(!granted||!s.server){reply({error:'افتح نافذة الإضافة لتحديد الخادم ومنح إذن الحماية أولًا.'});return;}}
await chrome.storage.local.set({enabled:!!msg.enabled});reply({enabled:!!msg.enabled});return;}
reply({error:'طلب غير مدعوم'});
})().catch(()=>reply({error:'تعذر تنفيذ الطلب'}));return true;});
