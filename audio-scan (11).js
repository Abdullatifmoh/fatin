"use strict";
// Audio upload and short user-initiated microphone captures, not internal call recording.
(function(){
 const $=s=>document.querySelector(s);
 const field=$('#audioValue'), label=$('#audioFilename');
 const start=$('#micStart'), stop=$('#micStop'), analyze=$('#micAnalyze'), discard=$('#micDiscard');
 const state=$('#micStatus'), player=$('#micPreview');
 const consent=$('#callConsent');
 let recorder=null, stream=null, pieces=[], clip=null, mime='', clipUrl=null, started=0, cutoff=null;
 const tell=text=>{state.textContent=text;};
 const release=()=>{if(cutoff){clearTimeout(cutoff);cutoff=null;}if(stream){stream.getTracks().forEach(t=>t.stop());stream=null;}};
 function forget(){release();clip=null;pieces=[];analyze.disabled=true;discard.disabled=true;
  if(clipUrl){URL.revokeObjectURL(clipUrl);clipUrl=null;}
  player.removeAttribute('src');player.hidden=true;player.load();}
 function format(){
  // Mobile Safari often records MP4, while Android/Chrome commonly records WebM.
  const list=['audio/webm;codecs=opus','audio/mp4','audio/webm','audio/ogg;codecs=opus'];
  return list.find(x=>window.MediaRecorder&&MediaRecorder.isTypeSupported(x))||'';
 }
 function saveBlob(){
  const actual=recorder&&recorder.mimeType||mime||'audio/webm';
  clip=new Blob(pieces,{type:actual});pieces=[];
  if(!clip.size){tell('لم يسجل الميكروفون أي صوت. حاول من جديد.');forget();return;}
  if(clip.size>5*1024*1024){tell('المقطع تجاوز 5 ميجابايت. سجّل مقطعًا أقصر.');forget();return;}
  clipUrl=URL.createObjectURL(clip);player.src=clipUrl;player.hidden=false;
  analyze.disabled=false;discard.disabled=false;
  tell('تم حفظ المقطع مؤقتًا داخل هذه الصفحة فقط. استمع إليه، ثم اضغط «حلّل المقطع» إذا أردت إرساله.');
 }
 field.addEventListener('change',()=>{const f=field.files&&field.files[0];label.textContent=f?('اخترت: '+f.name+' ('+Math.ceil(f.size/1024)+' كيلوبايت)'):'الحد الأقصى 5 ميجابايت.';});
 start.addEventListener('click',async()=>{
  if(!consent.checked){tell('وافق على شروط تسجيل الصوت أولًا.');return;}
  if(!navigator.mediaDevices||!navigator.mediaDevices.getUserMedia||!window.MediaRecorder){tell('الميكروفون أو التسجيل غير مدعوم في هذا المتصفح. يمكنك رفع تسجيل جاهز. يلزم HTTPS.');return;}
  forget();start.disabled=true;stop.disabled=true;
  try{
   stream=await navigator.mediaDevices.getUserMedia({audio:{echoCancellation:false,noiseSuppression:true},video:false});
   mime=format();recorder=mime?new MediaRecorder(stream,{mimeType:mime}):new MediaRecorder(stream);
   pieces=[];
   recorder.ondataavailable=e=>{if(e.data&&e.data.size)pieces.push(e.data);};
   recorder.onstop=()=>{release();start.disabled=false;stop.disabled=true;saveBlob();};
   recorder.onerror=()=>{release();start.disabled=false;stop.disabled=true;tell('حدث خطأ في التسجيل، يمكنك رفع ملف صوتي بدلًا منه.');};
   recorder.start();started=Date.now();stop.disabled=false;
   tell('🔴 جارٍ التسجيل… تحدث قريبًا من ميكروفون الجهاز. اضغط «إيقاف» عند اكتمال المقطع (30 ثانية كحد أقصى).');
   cutoff=setTimeout(()=>{if(recorder&&recorder.state==='recording')recorder.stop();},30000);
  }catch(err){release();start.disabled=false;stop.disabled=true;tell('تعذر فتح الميكروفون. اسمح بالوصول إليه وتأكد أن مكالمة الهاتف لا تمنع استخدامه، أو ارفع ملفًا مسجّلًا.');}
 });
 stop.addEventListener('click',()=>{if(recorder&&recorder.state==='recording')recorder.stop();});
 discard.addEventListener('click',()=>{if(recorder&&recorder.state==='recording')recorder.stop();forget();tell('حُذف المقطع من ذاكرة الصفحة ولم يُرسل.');});
 analyze.addEventListener('click',async()=>{
  if(!clip){tell('سجّل مقطعًا أولًا.');return;}
  if(!consent.checked||!$('#consent').checked){tell('يجب الموافقة على تسجيل المقطع وإرساله إلى فطن وGemini قبل التحليل.');return;}
  if(!navigator.onLine){tell('تحليل الصوت يحتاج اتصالًا بالإنترنت وGemini.');return;}
  analyze.disabled=true;tell('جارٍ إرسال المقطع وتحليل مؤشرات الاحتيال…');
  const extension=clip.type.includes('mp4')?'m4a':clip.type.includes('ogg')?'ogg':clip.type.includes('webm')?'webm':'webm';
  const form=new FormData();form.append('audio',clip,'fatin-clip.'+extension);form.append('ai_consent','true');
  try{const data=await api('audio',form);last=data;renderResult(data);makeReport(data);tell('اكتمل فحص التسجيل. اقرأ النتيجة ثم اضغط «اسمع النتيجة» لسماع الصوت النسائي.');document.querySelector('#result').scrollIntoView({behavior:'smooth',block:'start'});}
  catch(err){tell('تعذّر التحليل: '+err.message);}
  finally{analyze.disabled=!clip;}
 });
 window.addEventListener('pagehide',()=>{release();if(clipUrl)URL.revokeObjectURL(clipUrl);});
})();
