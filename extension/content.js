'use strict';
let banner=null;
function clearBanner(){if(banner){banner.remove();banner=null;}}
function showBanner(d){
 clearBanner();banner=document.createElement('div');banner.dataset.fatinBanner='true';
 banner.style.cssText='position:fixed;top:12px;left:12px;right:12px;z-index:2147483647;';
 const root=banner.attachShadow({mode:'closed'}),style=document.createElement('style');
 style.textContent='*{box-sizing:border-box}section{direction:rtl;font:14px/1.7 Arial,sans-serif;color:#fff;background:#392260;border:1px solid #b196d1;border-radius:13px;box-shadow:0 8px 30px #0004;padding:16px 22px;max-width:850px;margin:auto}header{display:flex;justify-content:space-between;gap:16px}b{font-size:17px}p{margin:8px 0}button,a{font:inherit;border:1px solid #ffffff50;border-radius:6px;padding:5px 10px;background:transparent;color:#fff;cursor:pointer;display:inline-block;margin:4px}ul{margin:8px 0;padding-right:20px}small{color:#e0cfee}';root.append(style);
 const section=document.createElement('section'),head=document.createElement('header'),title=document.createElement('b'),close=document.createElement('button');
 title.textContent='درع فطن · '+(d.risk==='high'?'تحقق قبل إدخال بياناتك':'نطاق يحتاج التحقق');close.textContent='إغلاق';close.onclick=clearBanner;head.append(title,close);
 const para=document.createElement('p');para.textContent=d.summary;section.append(head,para);
 const list=document.createElement('ul');for(const x of (d.indicators||[]).slice(0,4)){const li=document.createElement('li');li.textContent=x.title+': '+x.evidence+' — '+x.explanation;list.append(li);}section.append(list);
 const brand=FATIN_REGISTRY.find(b=>b.id===d.identity?.brand_id);
 if(brand){const link=document.createElement('a');link.href=brand.official_url;link.target='_blank';link.rel='noopener noreferrer';link.textContent='إكمال المهمة عبر '+brand.name;section.append(link);}
 const report=document.createElement('button');report.textContent='تنزيل تقرير المؤشرات';report.onclick=()=>{const clean={checked_url:location.origin+'/',checked_at:new Date().toISOString(),risk:d.risk,indicators:d.indicators,identity:d.identity,limitation:d.limitation};const url=URL.createObjectURL(new Blob([JSON.stringify(clean,null,2)],{type:'application/json'}));const a=document.createElement('a');a.href=url;a.download='fatin-evidence.json';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);};section.append(report);
 const note=document.createElement('small');note.textContent='لم تُقرأ قيم الحقول. لا يثبت هذا التحذير الاحتيال. '+(d.notice||'');section.append(document.createElement('br'),note);root.append(section);document.documentElement.append(banner);
}
chrome.runtime.onMessage.addListener(msg=>{if(msg.type==='fatin-result')showBanner(msg.result);if(msg.type==='fatin-clear')clearBanner();if(msg.type==='fatin-status')window.postMessage({source:'fatin-extension',type:'status',enabled:msg.enabled},location.origin);});
// Bridge is constrained by the configured dashboard inside the service worker.
window.addEventListener('message',async e=>{if(e.source!==window||e.origin!==location.origin||e.data?.source!=='fatin-web')return;if(!['get-status','set-protection'].includes(e.data.type))return;try{const r=await chrome.runtime.sendMessage({type:e.data.type,enabled:e.data.enabled});window.postMessage({source:'fatin-extension',type:r.error?'error':'status',message:r.error,enabled:r.enabled},location.origin);}catch{}});
(async()=>{try{const s=await chrome.storage.local.get('dashboard');if(!s.dashboard)return;const actual=new URL(location.href), expected=new URL(s.dashboard);if(actual.origin===expected.origin&&actual.pathname.replace(/\/$/,'')===expected.pathname.replace(/\/$/,'')){const r=await chrome.runtime.sendMessage({type:'get-status'});window.postMessage({source:'fatin-extension',type:'status',enabled:r.enabled},location.origin);}}catch{}})();

let active=false, previous='', scheduled=null;
function pageSnapshot(){
 // Only title/heading text and field TYPES. Never read input.value, labels or body text.
 const redact=t=>String(t).replace(/[\w.+-]+@[\w.-]+/g,'[بريد محذوف]').replace(/\d{3,}/g,'[أرقام محذوفة]');
 const u=new URL(location.href);u.search='';u.hash='';u.username='';u.password='';u.pathname='/';
 return {url:u.href,title:redact(document.title).slice(0,300),headings:redact(Array.from(document.querySelectorAll('h1,h2')).slice(0,4).map(n=>n.textContent).join(' ')).slice(0,600),password:!!document.querySelector('input[type="password"]'),payment:!!document.querySelector('input[autocomplete="cc-number"],input[autocomplete="cc-csc"],input[name="cardnumber"],input[name="card_number"]')};
}
async function inspectPage(){
 if(!active)return;const snap=pageSnapshot(),key=JSON.stringify(snap);if(key===previous)return;previous=key;
 const local=inspectIdentity(snap);if(['high','medium'].includes(local.risk))showBanner(local);else clearBanner();
 try{const d=await chrome.runtime.sendMessage({type:'scan-page',snapshot:snap});if(!active||previous!==key)return;if(d?.result&&['high','medium'].includes(d.result.risk))showBanner(d.result);if(d?.error&&['high','medium'].includes(local.risk)){local.notice='شرح الخادم غير متاح؛ التنبيه المحلي يعمل.';showBanner(local);}}catch{}
}
function queueInspection(){if(!active)return;clearTimeout(scheduled);scheduled=setTimeout(inspectPage,150);}
new MutationObserver(records=>{if(records.some(r=>!r.target.closest?.('[data-fatin-banner]')))queueInspection();}).observe(document,{childList:true,subtree:true,characterData:true,attributes:true,attributeFilter:['type','autocomplete','name']});
// Recheck on focus without collecting keystrokes or field values. No forced blocking.
document.addEventListener('focusin',e=>{if(active&&e.target.matches?.('input[type="password"],input[autocomplete^="cc-"]')){previous='';inspectPage();}},true);
chrome.runtime.onMessage.addListener(msg=>{if(msg.type==='fatin-status'){active=!!msg.enabled;previous='';if(active)inspectPage();else clearBanner();}});
(async()=>{try{const r=await chrome.runtime.sendMessage({type:'get-status'});active=!!r.enabled;inspectPage();}catch{}})();
