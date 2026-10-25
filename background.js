// Per-tab warning badge. No browsing history or page content is transmitted.
chrome.runtime.onMessage.addListener((message,sender)=>{
 if(message?.type!=='FATIN_RISK'||!sender.tab?.id)return;
 const tabId=sender.tab.id;
 chrome.action.setBadgeBackgroundColor({tabId,color:message.risk?'#b42318':'#6b7280'}).catch(()=>{});
 chrome.action.setBadgeText({tabId,text:message.risk?'!':''}).catch(()=>{});
});
chrome.storage.onChanged.addListener((changes,area)=>{
 if(area==='local'&&changes.protectionEnabled?.newValue===false){
  chrome.tabs.query({}, tabs=>tabs.forEach(t=>{if(t.id)chrome.action.setBadgeText({tabId:t.id,text:''}).catch(()=>{});}));
 }
});
