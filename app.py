        app.logger.warning("AI analysis unavailable; using indicator rules")
        fallback["notice"] = "تعذر الاتصال بـGemini أو قراءة نتيجته؛ عُرض فحص أولي محدود."
        return fallback


@app.get("/")
def home():
    return app.send_static_file("index.html")


@app.get("/<filename>")
def frontend_asset(filename):
    if filename not in {"style.css", "app.js"}:
        return jsonify(error="الصفحة غير موجودة."), 404
    return app.send_static_file(filename)


@app.get("/api/health")
def health():
    return jsonify(status="ok", ai_configured=bool(client), model=MODEL,
        fallback_models=FALLBACK_MODELS, requires_token=bool(TOKEN))


@app.post("/api/analyze")
def analyze_route():
    try:
        data = payload()
        consent(data)
        kind, value = data.get("kind"), data.get("value")
        if kind not in {"url", "text"} or not isinstance(value, str) or not value.strip() or len(value) > 20000:
            raise ValueError("أدخل رابطًا أو نصًا بين 1 و20000 حرف.")
        if kind == "url":
            clean_url(value)
        result = analyze(url=value) if kind == "url" else analyze(text=value)
        return jsonify(result)
    except ValueError as e:
        return jsonify(error=str(e)), 400


@app.post("/api/file")
def file_route():
    if request.form.get("ai_consent") != "true":
        return jsonify(error="أكد الموافقة على إرسال الملف للفحص."), 400
    upload = request.files.get("file")
    if not upload or not upload.filename:
        return jsonify(error="اختر ملفًا للفحص."), 400
    blob = upload.read(5 * 1024 * 1024 + 1)
    if not blob or len(blob) > 5 * 1024 * 1024:
        return jsonify(error="اختر ملفًا غير فارغ لا يتجاوز 5 ميجابايت."), 400
    filename = upload.filename.replace("\\", "/").split("/")[-1][:180]
    ext = os.path.splitext(filename)[1].lower()
    mime = None
    text = ""
    if ext in {".txt", ".eml", ".csv", ".json", ".html", ".log"}:
        try:
            text = blob.decode("utf-8-sig")
        except UnicodeError:
            return jsonify(error="احفظ الملف النصي بترميز UTF-8 ثم أعد رفعه."), 400
        if len(text) > 20000:
            return jsonify(error="الملف النصي يتجاوز 20000 حرف؛ ارفع مقتطفًا أصغر."), 400
    elif ext == ".pdf" and blob.startswith(b"%PDF-"):
        mime = "application/pdf"
    elif ext == ".png" and blob.startswith(b"\x89PNG\r\n\x1a\n"):
        mime = "image/png"
    elif ext in {".jpg", ".jpeg"} and blob.startswith(b"\xff\xd8\xff"):
        mime = "image/jpeg"
    else:
        return jsonify(error="الصيغ المدعومة: TXT وEML وCSV وJSON وHTML وPDF وPNG وJPG. لا تُشغّل الملفات التنفيذية."), 400
    result = analyze(text=text, filename=filename, binary=blob if mime else None, mime=mime)
    if mime and result["engine"] == "rules":
        result["notice"] = "لم يُفحص محتوى الصورة أو PDF لأن Gemini غير متاح؛ تم حساب بصمة الملف فقط."
    result["file"] = {"name": filename, "bytes": len(blob), "sha256": hashlib.sha256(blob).hexdigest()}
    return jsonify(result)


@app.post("/api/chat")
def chat_route():
    try:
        data = payload()
        consent(data)
        msg = data.get("message")
        if not isinstance(msg, str) or not msg.strip() or len(msg) > 4000:
            raise ValueError("أدخل سؤالًا لا يتجاوز 4000 حرف.")
        if not client:
            return jsonify(response="المستشار يحتاج تفعيل Gemini على الخادم. للتحقق من رسالة مشبوهة استخدم قسم الفحص؛ ولا تشارك كلمة المرور أو رمز التحقق.", engine="rules")
        context = data.get("context", "")
        if not isinstance(context, str):
            context = ""
        answer, used_model = generate_with_fallback(
            json.dumps({"question": msg, "analysis_context": context[:6000]}, ensure_ascii=False),
            {"system_instruction": SYSTEM + " قدم إرشادًا مختصرًا للمستخدم بناء على السؤال؛ لا تصنف الأسئلة التعليمية تهديدًا.", "max_output_tokens": 1000},
            parse_chat)
        return jsonify(response=answer, engine="gemini", model=used_model)
    except ValueError as e:
        return jsonify(error=str(e)), 400
    except Exception:
        return jsonify(error="المستشار غير متاح مؤقتًا؛ حاول لاحقًا."), 503


@app.post("/api/browser-check")
def browser_route():
    try:
        data = payload()
        consent(data)
        raw = data.get("url", "")
        safe, _ = clean_url(raw)
        # Keep the credentials indicator, but never send credentials to Gemini.
        key = hashlib.sha256(raw.encode()).hexdigest()
        now = time.monotonic()
        with lock:
            hit = cache.get(key)
        if hit and now - hit[0] < 300:
            return jsonify(hit[1])
        result = analyze(url=raw)
        result["checked_url"] = safe
        with lock:
            cache[key] = (now, result)
            while len(cache) > 200:
                cache.popitem(last=False)
        return jsonify(result)
    except ValueError as e:
        return jsonify(error=str(e)), 400


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.getenv("PORT", "5000")), debug=False)
