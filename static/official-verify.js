"use strict";
// Public, user-initiated referral to the official Tahqaq service. No NCA API calls.
const FatinTahqaq = (() => {
  const HASEEN = 'https://tahqaq.haseen.gov.sa/';
  const WHATSAPP = 'https://wa.me/966118136644';
  function safePublicUrl(raw) {
    if (typeof raw !== 'string' || raw.length > 2048) return '';
    try {
      const url = new URL(raw.trim());
      if (!['https:', 'http:'].includes(url.protocol) || url.username || url.password) return '';
      if (!url.hostname || /[\s]/.test(url.hostname)) return '';
      // Never forward query strings/fragments: they may contain passwords, OTPs or session IDs.
      url.search = ''; url.hash = '';
      return url.href;
    } catch (_) { return ''; }
  }
  async function copyUrl(url, status, manual) {
    if (!url) { status.textContent = 'لا يوجد رابط صالح. افحص رابطًا أولًا أو أدخله في خانة الرابط.'; return; }
    try {
      if (!navigator.clipboard || !navigator.clipboard.writeText) throw new Error('unsupported');
      await navigator.clipboard.writeText(url);
      status.textContent = 'تم نسخ الرابط دون الاستعلامات والجزء بعد #. راجعه واحذف أي معلومات خاصة قبل لصقه في تحقّق.';
    } catch (_) {
      if (manual) {
        manual.hidden = false;
        const input = manual.querySelector('input');
        input.value = url;
        input.focus();input.select();
        status.textContent = 'انسخ الرابط من المربع يدويًا ثم افتح تحقّق.';
      } else {
        status.textContent = 'تعذر النسخ تلقائيًا. انتقل إلى صفحة تحقّق الرسمي لنسخ الرابط يدويًا.';
      }
    }
  }
  function appendResult(out, result) {
    const panel = document.createElement('div');
    panel.className = 'official-result';
    const title = document.createElement('strong');
    title.textContent = '🔍 فحص إضافي عبر خدمة «تحقّق» الرسمية';
    const description = document.createElement('p');
    description.textContent = 'الخدمة الرسمية تدعم فحص الروابط والملفات ورموز QR. لا تُرسل نتائج فطن أو الصوت تلقائيًا، ويحتاج فتح الخدمة إلى الإنترنت.';
    const buttons = document.createElement('div');buttons.className = 'official-actions';
    const official = document.createElement('a'); official.className = 'primary button';
    official.href = HASEEN;official.target = '_blank';official.rel = 'noopener noreferrer';
    official.textContent = 'فتح خدمة تحقّق ↗';
    const whatsapp = document.createElement('a');whatsapp.className = 'secondary button';
    whatsapp.href = WHATSAPP;whatsapp.target = '_blank';whatsapp.rel = 'noopener noreferrer';
    whatsapp.textContent = 'واتساب تحقّق';
    buttons.append(official,whatsapp);
    const url = result.demo ? '' : safePublicUrl(result.checked_url || '');
    const status = document.createElement('p');status.className = 'official-status';status.setAttribute('role','status');
    if (url) {
      const copy = document.createElement('button');copy.type = 'button';
      copy.className = 'secondary';copy.textContent = 'نسخ الرابط للفحص الرسمي';
      copy.addEventListener('click', () => copyUrl(url,status,null));
      buttons.prepend(copy);
    } else if (result.media_type === 'audio') {
      status.textContent = 'بعد تحليل المكالمة، إذا سمعت رابطًا مشبوهًا فاكتبه في فحص الروابط أولًا، ثم استخدم خدمة تحقّق.';
    } else {
      status.textContent = 'إذا كان لديك ملف أو رمز QR، ارفعه بنفسك عبر بوابة حصين الرسمية.';
    }
    const disclaimer = document.createElement('small');
    disclaimer.textContent = 'فطن جهة مستقلة ولا يرتبط تقنيًا بمنصة تحقّق أو يمثل الهيئة.';
    panel.append(title,description,buttons,status,disclaimer); out.append(panel);
  }
  function init() {
    const copy = document.getElementById('copyTahqaqUrl');
    const tell = document.getElementById('tahqaqStatus');
    const manual = document.getElementById('tahqaqManualCopy');
    const speak = document.getElementById('speakTahqaqHelp');
    if (!copy || !tell || !manual || !speak) return;
    copy.addEventListener('click', () => {
      const lastUrl = (typeof last !== 'undefined' && last && !last.demo) ? last.checked_url : '';
      const current = document.getElementById('urlValue')?.value || '';
      const url = safePublicUrl(lastUrl || current);
      manual.hidden = true;
      copyUrl(url,tell,manual);
    });
    speak.addEventListener('click', () => {
      if (typeof FatinVoice !== 'undefined') {
        FatinVoice.speak('هلا بك. إذا وصلك رابط غريب، افحصه أول شيء في فطن. وبعدها اضغط نسخ الرابط. افتح خدمة تحقّق الرسمية في بوابة حصين أو واتساب. الصق الرابط بنفسك وانتظر النتيجة. لا تعطي أي شخص رمز تحقق أو رقم بطاقة أو كلمة مرور.');
      } else {tell.textContent = 'تعذر تشغيل الشرح الصوتي على هذا الجهاز.';}
    });
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded',init);
  else init();
  return { safePublicUrl, appendResult };
})();
