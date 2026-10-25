import io
import json
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock
import pytest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import app as m
from google.genai import types

VALID = {'risk':'unknown','summary':'تحليل مكتمل','indicators':[],'actions':['تحقق من المصدر']}
@pytest.fixture(autouse=True)
def setup(monkeypatch):
    m.cooldowns.clear(); m.buckets.clear()
    monkeypatch.setattr(m,'TOKEN','')
    monkeypatch.setattr(m,'MODEL','test-primary')
    monkeypatch.setattr(m,'FALLBACK_MODELS',['test-secondary'])
    generate=Mock(return_value=SimpleNamespace(text=json.dumps(VALID)))
    monkeypatch.setattr(m,'client',SimpleNamespace(models=SimpleNamespace(generate_content=generate)))
    yield generate

def test_title_url_still_calls_ai(setup):
    r=m.app.test_client().post('/api/analyze',json={'kind':'url','value':'https://unknown.example.com/login','title':'صفحة جديدة','ai_consent':True})
    assert r.status_code==200 and r.json['engine']=='gemini'
    setup.assert_called_once()
    assert r.json['identity']['domain']=='unknown.example.com'

def test_identity_evidence_preserved(setup):
    r=m.app.test_client().post('/api/analyze',json={'kind':'url','value':'https://fake.example.com','title':'جامعة الملك فيصل','password':True,'ai_consent':True})
    assert r.json['engine']=='gemini' and r.json['risk']=='high'
    assert r.json['identity']['domain_match'] is False

def test_timeout_and_sdk_configuration(setup):
    m.analyze(text='رسالة')
    config=setup.call_args.kwargs['config']
    assert 24000 <= config['http_options']['timeout'] <= 25000
    types.GenerateContentConfig(**config)

def test_fallback_after_model_not_found(setup):
    e=RuntimeError('not shown');e.code=404
    setup.side_effect=[e,SimpleNamespace(text=json.dumps(VALID))]
    assert m.analyze(text='hello')['model']=='test-secondary'
    assert setup.call_count==2

@pytest.mark.parametrize('code,reason',[(400,'invalid_request'),(401,'authentication'),(403,'permission'),(429,'quota'),(503,'provider_error')])
def test_errors_explained_without_secrets(setup,code,reason):
    e=RuntimeError('SECRET_KEY_AND_USER_CONTENT');e.code=code
    setup.side_effect=e
    result=m.analyze(text='hello')
    assert result['ai_error']==reason and result['engine']=='rules'
    assert 'SECRET' not in json.dumps(result)
    if code in [400,401,403]: assert setup.call_count==1

def test_invalid_json(setup):
    setup.return_value=SimpleNamespace(text='not json')
    assert m.analyze(text='hello')['ai_error']=='invalid_response'

def test_png_passed_as_binary(setup):
    blob=b'\x89PNG\r\n\x1a\n' + b'test'
    r=m.app.test_client().post('/api/file',data={'ai_consent':'true','file':(io.BytesIO(blob),'sample.png')})
    assert r.status_code==200 and r.json['engine']=='gemini'
    assert setup.call_args.kwargs['contents'][1].inline_data.data==blob

def test_chat(setup):
    setup.return_value=SimpleNamespace(text='إرشاد')
    r=m.app.test_client().post('/api/chat',json={'message':'كيف أتحقق؟','ai_consent':True})
    assert r.json['engine']=='gemini' and r.json['response']=='إرشاد'

def test_no_consent_does_not_send(setup):
    assert m.app.test_client().post('/api/analyze',json={'kind':'text','value':'hello'}).status_code==400
    setup.assert_not_called()

def test_no_key(monkeypatch):
    monkeypatch.setattr(m,'client',None)
    assert m.analyze(text='hello')['engine']=='rules'

def test_static_assets():
    c=m.app.test_client()
    for path in ['/','/app.js','/identity.js','/style.css']:
        assert c.get(path).status_code==200
    root=Path(m.__file__).parent
    js=(root/'app.js').read_text()
    assert "path='browser-check'" not in js
    assert 'body={kind,value,title:' in js
    assert (root/'static/app.js').read_text()==js
