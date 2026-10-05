import json
from pathlib import Path
from urllib.parse import urlsplit

REGISTRY = json.loads(Path(__file__).with_name("registry.json").read_text())

def inspect_identity(snapshot):
    host = urlsplit(snapshot["url"]).hostname.lower()
    title = str(snapshot.get("title", "")).lower()[:300]
    headings = str(snapshot.get("headings", "")).lower()[:600]
    password = snapshot.get("password") is True
    payment = snapshot.get("payment") is True
    matches = [b for b in REGISTRY if any(a.lower() in title or a.lower() in headings for a in b["aliases"])]
    brand = matches[0] if len(matches) == 1 else None
    match = bool(brand and any(host == d or host.endswith("." + d) for d in brand["domains"]))
    risk = "unknown"
    summary = "الأدلة غير كافية لتحديد الجهة؛ لا تعتبر هذه النتيجة شهادة سلامة."
    rows = []
    if brand:
        rows.append({"title": "الجهة الظاهرة", "evidence": brand["name"], "explanation": "اسم الجهة موجود في عنوان الصفحة أو عناوينها؛ الذكر وحده لا يثبت الانتحال."})
        if match:
            summary = "النطاق يطابق القائمة المرجعية لهذه الجهة. لم تُفحص سلامة الصفحة أو الحساب."
        else:
            risk = "high" if password or payment else "medium"
            summary = "اسم جهة موثقة على نطاق مختلف مع طلب بيانات حساسة؛ تحقق قبل المتابعة." if password or payment else "اسم جهة موثقة على نطاق غير مدرج؛ قد يكون ذكرًا عاديًا أو خدمة خارجية تحتاج التحقق."
            rows.append({"title": "اختلاف النطاق", "evidence": host, "explanation": "لا يطابق " + "، ".join(brand["domains"]) + "؛ القائمة محدودة ولا تغطي جميع مزودي الدخول الخارجيين."})
            if password or payment:
                rows.append({"title": "طلب بيانات حساسة", "evidence": " / ".join(x for x in ["حقل كلمة مرور" if password else "", "حقل دفع" if payment else ""] if x), "explanation": "اكتُشف نوع الحقل فقط. لم تُقرأ قيم الحقول."})
    return {"risk": risk, "summary": summary, "indicators": rows,
        "actions": ["تحقق من الجهة قبل إدخال البيانات.", "افتح القناة الرسمية من القائمة المرجعية لإكمال المهمة."] if brand and not match else ["تحقق من السياق والجهة؛ عدم ظهور تحذير لا يثبت السلامة."],
        "engine": "rules", "identity": {"brand_id": brand["id"] if brand else None, "brand": brand["name"] if brand else None, "domain": host, "domain_match": match, "sensitive_fields": password or payment, "official_url": brand["official_url"] if brand else None, "reviewed": brand["reviewed"] if brand else None},
        "limitation": "تحقق محدود من انتحال جهتين. لا تُقرأ قيم حقول الدخول أو الدفع، ولا يثبت الفحص سلامة الموقع."}
