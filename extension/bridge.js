(() => {
 'use strict';
 // Only installed on the user's Fatin website, not third-party websites.
 if(!['https://abdullatifmoh.github.io','https://fatin.onrender.com'].includes(location.origin))return;
 const send=(type,extra={})=>window.postMessage({source:'fatin-extension',type,...extra},location.origin);
 function status(){chrome.storage.local.get({protectionEnabled:false},data=>send('status',{enabled:data.protectionEnabled===true}));}
 window.addEventListener('message',event=>{
  if(event.source!==window || event.origin!==location.origin || event.data?.source!=='fatin-web')return;
  if(event.data.type==='get-status'){status();return;}
  if(event.data.type==='set-protection' && typeof event.data.enabled==='boolean'){
   chrome.storage.local.set({protectionEnabled:event.data.enabled},()=>{
    if(chrome.runtime.lastError)send('error',{message:'تعذر حفظ حالة الحماية: '+chrome.runtime.lastError.message});
    else status();
   });
  }
 });
 chrome.storage.onChanged.addListener((changes,area)=>{if(area==='local' && changes.protectionEnabled)status();});
 status();
})();