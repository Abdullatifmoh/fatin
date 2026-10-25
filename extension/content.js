(() => {
 'use strict';
 // Privacy: no input.value, clipboard, network, DOM text body, or credentials are collected.
 const REGISTRY = [{"id": "kfu", "name": "جامعة الملك فيصل", "aliases": ["جامعة الملك فيصل", "king faisal university"], "domains": ["kfu.edu.sa"], "official_url": "https://www.kfu.edu.sa/", "source": "https://www.kfu.edu.sa/", "reviewed": "2026-10-05"}, {"id": "spl", "name": "البريد السعودي | سبل", "aliases": ["البريد السعودي", "سبل", "saudi post", "spl online"], "domains": ["splonline.com.sa"], "official_url": "https://splonline.com.sa/ar/", "source": "https://splonline.com.sa/ar/", "reviewed": "2026-10-05"}];
 let enabled = false;
 let banner = null;
 let lastSignature = '';
 let updateTimer = null;
 const normal = s => String(s||'').toLocaleLowerCase().normalize('NFKC');
 const isDomain = (host, root) => host === root || host.endsWith('.'+root);
 function inspectPage(){
   const host = location.hostname.toLowerCase();
   const heading = [...document.querySelectorAll('h1,h2')].slice(0,4).map(x=>x.textContent.slice(0,150)).join(' ');
   const title = normal(document.title+' '+heading);
   const password = !!document.querySelector('input[type="password"],input[autocomplete="current-password"],input[autocomplete="new-password"]');
   const payment = !!document.querySelector('input[autocomplete^="cc-"],input[name="cardnumber"],input[id="cardNumber"]');
   const matches=REGISTRY.filter(b=>b.aliases.some(a=>title.includes(normal(a))));
   const claimed=matches.length===1 ? matches[0] : null;
   if(claimed && !claimed.domains.some(d=>isDomain(host,d)) && (password || payment)){
     return {severity:'high', title:'انتبه! ربما يوجد انتحال جهة', message:'تظهر الصفحة باسم «'+claimed.name+'» لكن النطاق '+host+' غير موجود في قائمة نطاقاتها، وتطلب '+(password?'بيانات دخول':'بيانات دفع')+'. لا تدخل بياناتك قبل التأكد.', official:claimed.official_url};
   }
   if(location.protocol==='http:' && (password || payment)){
     return {severity:'high',title:'تنبيه: إدخال بيانات على اتصال غير مشفّر',message:'الصفحة تطلب بيانات حساسة عبر HTTP. تحقق من الرابط قبل المتابعة.',official:''};
   }
   if(host.includes('xn--') && (password || payment)){
     return {severity:'medium',title:'تنبيه: تحقق من تهجئة الموقع',message:'النطاق يستخدم ترميزًا دوليًا ويطلب بيانات حساسة. قد يكون مشروعًا، لكن تأكد من اسم الجهة.',official:''};
   }
   return null;
 }
 function clearBanner(){if(banner){banner.remove();banner=null;}chrome.runtime.sendMessage({type:'FATIN_RISK',risk:false}).catch(()=>{});lastSignature='';}
 function warn(info){
   const signature=info.title+'|'+info.message;
   if(signature===lastSignature&&banner)return;
   if(banner)banner.remove();lastSignature=signature;
   banner=document.createElement('section');banner.id='fatin-warning-banner';
   Object.assign(banner.style,{position:'fixed',top:'12px',left:'12px',right:'12px',zIndex:'2147483647',boxSizing:'border-box',background:'#301959',color:'#fff',fontFamily:'Tahoma,Arial,sans-serif',fontSize:'16px',border:'3px solid #fbad65',borderRadius:'16px',padding:'18px',direction:'rtl',textAlign:'right',boxShadow:'0 9px 35px #0006',lineHeight:'1.8'});
   banner.setAttribute('role','alert');banner.setAttribute('aria-live','assertive');
   const heading=document.createElement('strong');heading.textContent='🛡️ درع فطن — '+info.title;
   heading.style.fontSize='19px';
   const p=document.createElement('p');p.textContent=info.message;p.style.margin='7px 0';
   const note=document.createElement('small');note.textContent='فحص قواعد محليّ: هذا مؤشر يستدعي التحقق، وليس إثباتًا على أن الموقع خبيث. لا نقرأ كلمات المرور أو قيم الحقول.';note.style.display='block';
   const close=document.createElement('button');close.textContent='فهمت، إغلاق التحذير';close.type='button';
   Object.assign(close.style,{marginTop:'12px',fontSize:'15px',padding:'9px 14px',cursor:'pointer',border:'none',borderRadius:'9px',background:'#fff',color:'#301959'});
   close.addEventListener('click',()=>{banner?.remove();banner=null;});
   banner.append(heading,p,note,close);
   if(info.official){const a=document.createElement('a');a.href=info.official;a.textContent='فتح الموقع الرسمي ↗';a.target='_blank';a.rel='noopener noreferrer';Object.assign(a.style,{display:'inline-block',padding:'8px',color:'#d2ffed'});banner.append(a);}
   (document.body||document.documentElement).append(banner);
   chrome.runtime.sendMessage({type:'FATIN_RISK',risk:true}).catch(()=>{});
 }
 function assess(){if(!enabled){clearBanner();return;}const info=inspectPage();if(info)warn(info);else clearBanner();}
 function schedule(){clearTimeout(updateTimer);updateTimer=setTimeout(assess,500);}
 chrome.storage.local.get({protectionEnabled:false}, data=>{enabled=data.protectionEnabled===true;assess();});
 chrome.storage.onChanged.addListener((changes,area)=>{if(area==='local' && changes.protectionEnabled){enabled=changes.protectionEnabled.newValue===true;schedule();}});
 // Only observe structural changes, never the typed field values.
 new MutationObserver(mutations=>{if(mutations.some(m=>m.type==='childList'||m.attributeName==='type'||m.attributeName==='autocomplete'))schedule();})
   .observe(document.documentElement,{subtree:true,childList:true,attributes:true,attributeFilter:['type','autocomplete']});
 document.addEventListener('visibilitychange',()=>{if(!document.hidden)schedule();});
})();