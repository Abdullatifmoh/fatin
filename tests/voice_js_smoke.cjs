// Mock browser/audio to test consent boundary, speech source and MP3 playback.
const vm=require('node:vm'),fs=require('node:fs'),assert=require('node:assert/strict');
const listeners={};const store={};
const element=id=>({id,checked:false,value:id==='voiceRate'?'0.8':undefined,hidden:true,src:'',textContent:'',
  addEventListener:(name,cb)=>{listeners[id+':'+name]=cb},removeAttribute(k){this[k]=''},
  pause(){},load(){},play(){this.played=true;return Promise.resolve()}});
const els=Object.fromEntries(['voiceStatus','voicePlayer','cloudVoiceConsent','voiceRate','voiceWelcome','stopVoice','largeText'].map(id=>[id,element(id)]));
const localStorage={getItem:key=>store[key]||null,setItem:(key,value)=>store[key]=value};
const sessionStorage={getItem:()=>''};let called=[];let localReads=[];
const ctx={document:{querySelector:sel=>els[sel.slice(1)],body:{classList:{toggle(){}}}},
 window:{SpeechSynthesisUtterance:function(text){this.text=text},speechSynthesis:{getVoices:()=>[{lang:'ar-SA',name:'Zariyah'}],cancel(){},speak(u){localReads.push(u.text);u.onend() }, addEventListener(){},onvoiceschanged:null}},
 navigator:{},location:{hostname:'abdullatifmoh.github.io'},localStorage,sessionStorage,
 SpeechSynthesisUtterance:function(text){this.text=text},
 URL:{createObjectURL:()=> 'blob:test', revokeObjectURL(){}}, AbortController,
 fetch:async(url,opts)=>{called.push({url,body:JSON.parse(opts.body)});return {ok:true,blob:async()=>({type:'audio/mpeg',size:4})}},
 setTimeout,clearTimeout,console};
vm.createContext(ctx);
vm.runInContext(fs.readFileSync(__dirname+'/../voice.js','utf8'),ctx);
(async()=>{
 await vm.runInContext('FatinVoice.speak("هلا بك في درع فطن")',ctx);
 assert.equal(called.length,0,'No cloud request without consent');
 assert.ok(localReads.length>0,'Local Arabic voice fallback');
 els.cloudVoiceConsent.checked=true;
 await vm.runInContext('FatinVoice.speak("هلا بك في درع فطن")',ctx);
 assert.equal(called.length,1,'One request after consent');
 assert.ok(called[0].url.endsWith('/api/voice'));
 assert.equal(called[0].body.voice_consent,true);
 assert.equal(els.voicePlayer.played,true);
 console.log('Voice JavaScript consent + playback checks passed');
})().catch(e=>{console.error(e);process.exit(1)});
