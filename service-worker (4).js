"use strict";
const VERSION="fatin-mobile-v3-unified-voice";
const SHELL=["./", "./index.html", "./style.css", "./identity.js", "./voice.js", "./app.js", "./audio-scan.js", "./official-verify.js", "./manifest.webmanifest", "./icons/fatin-192.png", "./icons/fatin-512.png"];
self.addEventListener("install",event=>{event.waitUntil(caches.open(VERSION).then(cache=>cache.addAll(SHELL)).then(()=>self.skipWaiting()))});
self.addEventListener("activate",event=>{event.waitUntil(caches.keys().then(keys=>Promise.all(keys.filter(key=>key!==VERSION&&key.startsWith("fatin-mobile-")).map(key=>caches.delete(key)))).then(()=>self.clients.claim()))});
self.addEventListener("fetch",event=>{
 const req=event.request,url=new URL(req.url);
 if(req.method!=="GET"||url.origin!==self.location.origin||url.pathname.includes("/api/"))return;
 if(req.mode==="navigate"){
  event.respondWith(fetch(req).then(res=>{if(res.ok){const copy=res.clone();caches.open(VERSION).then(c=>c.put("./",copy));}return res}).catch(()=>caches.match("./")));
  return;
 }
 event.respondWith(caches.match(req).then(cached=>cached||fetch(req)));
});
