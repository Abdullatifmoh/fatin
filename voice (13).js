"use strict";
// Explicit user-initiated Arabic speech, designed for touch devices and keyboard users.
const FatinVoice=(()=>{
 const status=document.querySelector('#voiceStatus'), player=document.querySelector('#voicePlayer');
 const optin=document.querySelector('#cloudVoiceConsent'), rate=document.querySelector('#voiceRate');
 let requestController=null, soundUrl=null, sequence=0, voiceSession=0;
 let localAvailable=typeof window.speechSynthesis!=='undefined'&&typeof window.SpeechSynthesisUtterance!=='undefined';
 function tell(s){status.textContent=s;}
 function stop(){sequence++;voiceSession++;if(requestController){requestController.abort();requestController=null}player.pause();player.removeAttribute('src');player.load();player.hidden=true;if(soundUrl){URL.revokeObjectURL(soundUrl);soundUrl=null}if(localAvailable)window.speechSynthesis.cancel();tell('توقف الصوت. يمكنك تشغيله مرة ثانية.');}
 function pickArabicVoice(){
  if(!localAvailable)return null;
  const voices=window.speechSynthesis.getVoices();
  const arabic=voices.filter(v=>/^ar(?:[-_]|$)/i.test(v.lang));
  const female=/Zariyah|Zaria|Salma|Hoda|Huda|Laila|Layla|Mariam|Maryam|Amal|Noura|Noora|Rana|Female|بنت|امرأة|أنثى/i;
  return arabic.find(v=>/^ar[-_]SA$/i.test(v.lang)&&female.test(v.name)) ||
   arabic.find(v=>female.test(v.name)) ||arabic.find(v=>/^ar[-_]SA$/i.test(v.lang)) ||arabic[0] ||null;
 }
 function deviceVoice(text){
  if(!localAvailable){tell('صوت الجهاز غير متاح هنا. فعّل صوت زارية عبر الإنترنت أو جرّب متصفحًا حديثًا.');return false;}
  const voice=pickArabicVoice();
  if(!voice){tell('لم أجد صوتًا عربيًا على الجهاز. فعّل الصوت النسائي السعودي عبر الإنترنت، أو ثبّت صوتًا عربيًا من إعدادات الهاتف.');return false;}
  window.speechSynthesis.cancel();
  const id=++voiceSession;
  const parts=[];
  // Small pieces prevent very long utterances from silently failing on some mobile devices.
  const sentences=text.match(/[^.،؛!؟\n]+[.،؛!؟\n]?/g)||[text];let part='';
  for(const s of sentences){if(part.length+s.length>150&&part){parts.push(part);part=''}if(s.length>160){for(let i=0;i<s.length;i+=135)parts.push(s.slice(i,i+135));}else part+=s;}
  if(part)parts.push(part);
  let cursor=0;
  const next=()=>{if(id!==voiceSession||cursor>=parts.length){if(id===voiceSession)tell('انتهت القراءة بصوت الجهاز.');return;}
   const u=new SpeechSynthesisUtterance(parts[cursor++]);u.lang='ar-SA';u.voice=voice;u.rate=Number(rate.value)||0.8;u.pitch=1;
   u.onend=next;u.onerror=(e)=>{if(id===voiceSession)tell('تعذر تشغيل صوت الجهاز. يمكنك تجربة الصوت السعودي عبر الإنترنت.')};
   window.speechSynthesis.speak(u);
  };
  tell('جاري القراءة بصوت الجهاز؛ جودة اللهجة تعتمد على الأصوات المتوفرة عندك.');next();return true;
 }
 function resultText(d,riskName){
  // Speak the decision, interpretation and safe actions, not raw URL evidence or document content.
  const intro= d.risk==='high'?'انتبه. ظهرت علامات قد تدل على محاولة احتيال.':d.risk==='medium'?'خلّك حريص. فيه أشياء تحتاج تتأكد منها.':'النتيجة مو أكيدة. لازم تتأكد قبل تتصرف.';
  const brief=(d.summary||'').replace(/https?:\/\/\S+/g,'رابط').slice(0,280);
  const actions=(d.actions||[]).slice(0,3).map(a=>String(a).replace(/https?:\/\/\S+/g,'رابط')).join('. ');
  return ['هلا بك في درع فطن.',intro,brief,actions?'وش تسوي الحين؟ '+actions:'', 'ولا تعطي أحد رمز التحقق أو كلمة المرور.'].filter(Boolean).join(' ' ).slice(0,900);
 }
 async function speak(input){
  stop(); const text=String(input||'').replace(/<[^>]*>/g,' ').replace(/https?:\/\/\S+/g,'رابط').trim().slice(0,900);
  if(!text){tell('ما فيه نص لقراءته الآن.');return;}
  const current=++sequence;
  if(!optin.checked){deviceVoice(text);return;}
  tell('جاري تجهيز صوت زارية السعودي…');
  const controller=new AbortController();requestController=controller;
  try{
   const host=localStorage.getItem('fatin-server')||(location.hostname==='abdullatifmoh.github.io'?'https://fatin.onrender.com':'');
   const auth=sessionStorage.getItem('fatin-token')||'';
   const headers={'Content-Type':'application/json'};if(auth)headers.Authorization='Bearer '+auth;
   const timeout=setTimeout(()=>controller.abort(),21000);
   let response;
   try{response=await fetch(host.replace(/\/$/,'')+'/api/voice',{method:'POST',headers,body:JSON.stringify({text,voice_consent:true}),signal:controller.signal})}
   finally{clearTimeout(timeout)}
   if(!response.ok)throw new Error('service unavailable');
   const blob=await response.blob();if(!blob.type.includes('audio/')||!blob.size)throw new Error('invalid audio');
   if(current!==sequence)return;
   soundUrl=URL.createObjectURL(blob);player.src=soundUrl;player.hidden=false;
   player.onended=()=>tell('خلصت القراءة. اضغط ▶ إذا تبي تسمعها مرة ثانية.');
   try{await player.play();tell('الصوت النسائي السعودي شغّال الآن.');}
   catch{tell('الصوت جاهز. اضغط زر ▶ في مشغّل الصوت للتشغيل على جوالك.');}
  }catch(e){if(current!==sequence)return; if(e.name==='AbortError'){tell('تعذر تجهيز الصوت الآن؛ بنحاول بصوت الجهاز.');}else tell('خدمة الصوت السعودي ما اشتغلت؛ بنحاول بصوت الجهاز.');deviceVoice(text);}
  finally{if(requestController===controller)requestController=null;}
 }
 document.querySelector('#voiceWelcome').addEventListener('click',()=>speak('يا هلا فيك في درع فطن. نساعدك تتأكد من الروابط والرسائل المشبوهة قبل تشارك معلوماتك. اضغط على الفحص الذكي، وحط الرابط أو نص الرسالة، وبعد ظهور النتيجة اضغط زر اسمع النتيجة. وإذا شكّيت في رسالة، لا تضغط الرابط ولا تعطي أحد رمز التحقق.'));
 document.querySelector('#stopVoice').addEventListener('click',stop);
 document.querySelector('#largeText').addEventListener('change',e=>{document.body.classList.toggle('easy-mode',e.target.checked);localStorage.setItem('fatin-large-text',e.target.checked?'true':'false')});
 document.querySelector('#largeText').checked=localStorage.getItem('fatin-large-text')==='true';
 document.body.classList.toggle('easy-mode',document.querySelector('#largeText').checked);
 rate.value=localStorage.getItem('fatin-voice-rate')||'0.8';rate.addEventListener('change',()=>localStorage.setItem('fatin-voice-rate',rate.value));
 // The opt-in checkbox intentionally resets for each new page load.
 if(localAvailable&&window.speechSynthesis.onvoiceschanged!==undefined)window.speechSynthesis.addEventListener('voiceschanged',()=>{});
 return {speak,stop,resultText};
})();
