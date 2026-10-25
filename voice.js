"use strict";
// Human-recorded audio only. No generated speech or synthetic fallback.
const FatinVoice=(()=>{
 const status=document.querySelector('#voiceStatus'),player=document.querySelector('#voicePlayer');
 const rate=document.querySelector('#voiceRate');
 const clips={welcome:'audio/saudi-male/welcome.mp3'};
 function tell(message){if(status)status.textContent=message;}
 function stop(){player.pause();player.removeAttribute('src');player.load();player.hidden=true;tell('توقف الصوت.');}
 async function playClip(key){stop();const src=clips[key];if(!src){tell('هذه النتيجة متاحة كتابةً. لا يوجد تسجيل بشري لها حتى الآن.');return;}
  try{const r=await fetch(src,{method:'HEAD'});if(!r.ok)throw Error('missing');player.src=src;player.hidden=false;await player.play();tell('جاري تشغيل التسجيل بصوت رجل سعودي.');}
  catch{player.hidden=true;tell('لم يُضف التسجيل البشري بعد. يمكنك قراءة الإرشادات على الشاشة.');}}
 function speak(){return playClip('result');}
 function resultText(d){return [d.summary||'',...(d.actions||[]).slice(0,3)].join(' ');}
 document.querySelector('#voiceWelcome')?.addEventListener('click',()=>playClip('welcome'));
 document.querySelector('#stopVoice')?.addEventListener('click',stop);
 document.querySelector('#largeText')?.addEventListener('change',e=>{document.body.classList.toggle('easy-mode',e.target.checked);localStorage.setItem('fatin-large-text',String(e.target.checked));});
 const large=document.querySelector('#largeText');if(large){large.checked=localStorage.getItem('fatin-large-text')==='true';document.body.classList.toggle('easy-mode',large.checked);}
 if(rate){rate.value=localStorage.getItem('fatin-voice-rate')||'0.8';rate.addEventListener('change',()=>localStorage.setItem('fatin-voice-rate',rate.value));}
 return {speak,stop,resultText};
})();
