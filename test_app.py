import io
import json
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import app as module

class FatinTests(unittest.TestCase):
    def setUp(self):
        self.web = module.app.test_client()
        module.buckets.clear()
        module.cache.clear()
        self.patcher = patch.object(module, 'client', None)
        self.patcher.start()
    def tearDown(self):
        self.patcher.stop()
    def post(self, value, kind='text', **kwargs):
        return self.web.post('/api/analyze', json={'kind':kind,'value':value,'ai_consent':True,**kwargs})
    def test_assets(self):
        for path in ['/', '/style.css', '/app.js', '/api/health']:
            self.assertEqual(self.web.get(path).status_code,200)
        self.assertEqual(self.web.get('/app.py').status_code,404)
    def test_consent(self):
        self.assertEqual(self.post('hello',ai_consent=False).status_code,400)
    def test_threat_indicators(self):
        d=self.post('عاجل سيتم إيقاف حسابك، أرسل رمز التحقق فوراً').get_json()
        self.assertEqual(d['risk'],'high')
        self.assertEqual(d['engine'],'rules')
        self.assertGreaterEqual(len(d['indicators']),2)
    def test_no_safety_claim(self):
        self.assertEqual(self.post('مرحبا بك').get_json()['risk'],'unknown')
    def test_invalid_requests(self):
        for body in [[],{'kind':'url','value':123,'ai_consent':True},{'kind':'text','value':'x'*20001,'ai_consent':True}]:
            self.assertEqual(self.web.post('/api/analyze',json=body).status_code,400)
        for url in ['http://localhost/', 'http://127.0.0.1/', 'ftp://example.com/', 'https://example.com:abc']:
            self.assertEqual(self.post(url,'url').status_code,400)
    def test_url_redaction(self):
        safe,_=module.clean_url('https://name:secret@example.com/login?token=secret#private')
        self.assertEqual(safe,'https://example.com/login')
        self.assertIn('بيانات مستخدم',self.post('https://name:secret@example.com/','url').get_json()['indicators'][0]['title'])
    def test_text_file(self):
        d=self.web.post('/api/file',data={'ai_consent':'true','file':(io.BytesIO('أرسل كلمة المرور فوراً'.encode()),'message.txt')}).get_json()
        self.assertEqual(d['risk'],'high')
        self.assertEqual(len(d['file']['sha256']),64)
    def test_unsupported_and_mismatch_file(self):
        for name in ['malware.exe','image.png','doc.pdf']:
            r=self.web.post('/api/file',data={'ai_consent':'true','file':(io.BytesIO(b'not the claimed type'),name)})
            self.assertEqual(r.status_code,400)
    def test_pdf_without_ai_is_unknown(self):
        d=self.web.post('/api/file',data={'ai_consent':'true','file':(io.BytesIO(b'%PDF-1.4 test'),'doc.pdf')}).get_json()
        self.assertEqual(d['risk'],'unknown')
        self.assertIn('لم يُفحص',d['notice'])
    def test_file_size(self):
        r=self.web.post('/api/file',data={'ai_consent':'true','file':(io.BytesIO(b'a'*(5*1024*1024+1)),'big.txt')})
        self.assertEqual(r.status_code,400)
    def test_ai_structured_output_and_redaction(self):
        fake=Mock()
        fake.models.generate_content.return_value=SimpleNamespace(text=json.dumps({'risk':'unknown','summary':'غير حاسم','indicators':[],'actions':['تحقق من المصدر']}))
        with patch.object(module,'client',fake):
            d=self.post('http://user:pass@example.com/a?secret=abcd','url').get_json()
            self.assertEqual(d['engine'],'gemini')
            self.assertEqual(d['risk'],'medium')
            sent=str(fake.models.generate_content.call_args.kwargs['contents'])
            self.assertNotIn('abcd',sent)
            self.assertNotIn('user:pass',sent)
            self.assertIn('response_json_schema',fake.models.generate_content.call_args.kwargs['config'])
    def test_ai_failure_and_bad_output(self):
        for output in ['not json', '{"risk":"safe"}']:
            fake=Mock()
            fake.models.generate_content.return_value=SimpleNamespace(text=output)
            with patch.object(module,'client',fake):
                self.assertEqual(self.post('hello').get_json()['engine'],'rules')
        fake.models.generate_content.side_effect=RuntimeError('secret-api-key')
        with patch.object(module,'client',fake):
            r=self.post('hello');self.assertNotIn('secret-api-key',r.get_data(as_text=True))
    def test_token_gate(self):
        with patch.object(module,'TOKEN','test-token'):
            self.assertEqual(self.post('hello').status_code,401)
            self.assertEqual(self.web.post('/api/analyze',json={'kind':'text','value':'hi','ai_consent':True},headers={'Authorization':'Bearer test-token'}).status_code,200)
    def test_rate_limit(self):
        for _ in range(20):
            self.assertEqual(self.post('hello').status_code,200)
        self.assertEqual(self.post('hello').status_code,429)
    def test_cors(self):
        r=self.web.options('/api/analyze',headers={'Origin':'https://attacker.example','Access-Control-Request-Method':'POST'})
        self.assertIsNone(r.headers.get('Access-Control-Allow-Origin'))
        r=self.web.options('/api/analyze',headers={'Origin':'https://abdullatifmoh.github.io','Access-Control-Request-Method':'POST'})
        self.assertEqual(r.headers.get('Access-Control-Allow-Origin'),'https://abdullatifmoh.github.io')
    def test_browser_result(self):
        d=self.web.post('/api/browser-check',json={'url':'https://example.com/?private=1','ai_consent':True}).get_json()
        self.assertEqual(d['checked_url'],'https://example.com/')
        self.assertEqual(d['risk'],'unknown')
    def test_chat_without_key(self):
        d=self.web.post('/api/chat',json={'message':'كيف أفحص رابط؟','ai_consent':True}).get_json()
        self.assertEqual(d['engine'],'rules')

if __name__=='__main__':unittest.main()
