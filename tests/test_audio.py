from pathlib import Path
import io
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]


def test_assets():
    html=(ROOT/'index.html').read_text()
    assert 'data-kind="audio"' in html
    for name in ('audioValue','micStart','micStop','micAnalyze','micDiscard','callConsent'):
        assert 'id="'+name+'"' in html
    assert (ROOT/'audio-scan.js').is_file()
    assert (ROOT/'static'/'audio-scan.js').is_file()


def test_audio_requires_explicit_consent():
    import app
    app.app.config['TESTING']=True
    c=app.app.test_client()
    resp=c.post('/api/audio',data={'audio':(io.BytesIO(b'ID3abc'),'voice.mp3')})
    assert resp.status_code==400


def test_audio_rejects_non_audio():
    import app
    app.app.config['TESTING']=True
    c=app.app.test_client()
    resp=c.post('/api/audio',data={'audio':(io.BytesIO(b'not audio'),'voice.mp3'),'ai_consent':'true'})
    assert resp.status_code==400


def test_audio_no_fake_rule_analysis(monkeypatch):
    import app
    app.app.config['TESTING']=True
    monkeypatch.setattr(app,'client',None)
    c=app.app.test_client()
    resp=c.post('/api/audio',data={'audio':(io.BytesIO(b'ID3'+b'\x00'*20),'voice.mp3'),'ai_consent':'true'})
    assert resp.status_code==503
    assert 'Gemini' in resp.json['error']


def test_audio_gemini_mock(monkeypatch):
    import app
    app.app.config['TESTING']=True
    monkeypatch.setattr(app,'client',object())
    monkeypatch.setattr(app,'generate_with_fallback',lambda contents,config,parse: ({'risk':'high','summary':'يوجد طلب رمز تحقق','indicators':[], 'actions':['لا تعطه الرمز'], 'transcript':'أرسل لي رمز التحقق'},'mock'))
    c=app.app.test_client()
    resp=c.post('/api/audio',data={'audio':(io.BytesIO(b'ID3'+b'\x00'*20),'voice.mp3'),'ai_consent':'true'})
    assert resp.status_code==200
    assert resp.json['transcript']=='أرسل لي رمز التحقق'
    assert resp.json['risk']=='high'
    assert resp.json['engine']=='gemini'
