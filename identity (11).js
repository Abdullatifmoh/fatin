"use strict";
const FATIN_REGISTRY = [{"id": "kfu", "name": "جامعة الملك فيصل", "aliases": ["جامعة الملك فيصل", "king faisal university"], "domains": ["kfu.edu.sa"], "official_url": "https://www.kfu.edu.sa/", "source": "https://www.kfu.edu.sa/", "reviewed": "2026-10-05"}, {"id": "spl", "name": "البريد السعودي | سبل", "aliases": ["البريد السعودي", "سبل", "saudi post", "spl online"], "domains": ["splonline.com.sa"], "official_url": "https://splonline.com.sa/ar/", "source": "https://splonline.com.sa/ar/", "reviewed": "2026-10-05"}];
function inspectIdentity(snapshot) {
 const u=new URL(snapshot.url), host=u.hostname.toLowerCase();
 const title=String(snapshot.title||'').toLowerCase().slice(0,300);
 const headings=String(snapshot.headings||'').toLowerCase().slice(0,600);
 const password=snapshot.password===true, payment=snapshot.payment===true;
 const matches=FATIN_REGISTRY.filter(b=>b.aliases.some(a=>title.includes(a.toLowerCase())||headings.includes(a.toLowerCase())));
 const brand=matches.length===1?matches[0]:null;
 const match=brand&&brand.domains.some(d=>host===d||host.endsWith('.'+d));
 let risk='unknown', summary='الأدلة غير كافية لتحديد الجهة؛ لا تعتبر هذه النتيجة شهادة سلامة.', indicators=[];
 if(brand){
  indicators.push({title:'الجهة الظاهرة',evidence:brand.name,explanation:'اسم الجهة موجود في عنوان الصفحة أو عناوينها؛ الذكر وحده لا يثبت الانتحال.'});
  if(match){summary='النطاق يطابق القائمة المرجعية لهذه الجهة. لم تُفحص سلامة الصفحة أو الحساب.';}
  else {risk=(password||payment)?'high':'medium';summary=(password||payment)?'اسم جهة موثقة على نطاق مختلف مع طلب بيانات حساسة؛ تحقق قبل المتابعة.':'اسم جهة موثقة على نطاق غير مدرج؛ قد يكون ذكرًا عاديًا أو خدمة خارجية تحتاج التحقق.';
   indicators.push({title:'اختلاف النطاق',evidence:host,explanation:'لا يطابق '+brand.domains.join('، ')+'؛ القائمة محدودة ولا تغطي جميع مزودي الدخول الخارجيين.'});
   if(password||payment)indicators.push({title:'طلب بيانات حساسة',evidence:[password?'حقل كلمة مرور':'',payment?'حقل دفع':''].filter(Boolean).join(' / '),explanation:'اكتُشف نوع الحقل فقط. لم تُقرأ قيم الحقول.'});
  }
 }
 return {risk,summary,indicators,actions:brand&&!match?['تحقق من الجهة قبل إدخال البيانات.','افتح القناة الرسمية من القائمة المرجعية لإكمال المهمة.']:['تحقق من السياق والجهة؛ عدم ظهور تحذير لا يثبت السلامة.'],engine:'rules',identity:{brand_id:brand?.id||null,brand:brand?.name||null,domain:host,domain_match:!!match,sensitive_fields:password||payment,official_url:brand?.official_url||null,reviewed:brand?.reviewed||null},limitation:'تحقق محدود من انتحال جهتين. لا يُقرأ محتوى حقول الدخول أو الدفع، ولا يثبت الفحص سلامة الموقع.'};
}
if(typeof module!=='undefined')module.exports={FATIN_REGISTRY,inspectIdentity};
