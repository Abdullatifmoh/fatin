"""Run after pip install -r requirements.txt pytest (no live Microsoft connection)."""
from pathlib import Path
import asyncio
import importlib.util

import pytest

ROOT = Path(__file__).resolve().parents[1]


def test_pwa_artifacts_exist():
    import json
    manifest = json.loads((ROOT / 'manifest.webmanifest').read_text())
    assert manifest['lang'] == 'ar-SA'
    assert manifest['display'] == 'standalone'
    for item in ('voice.js', 'service-worker.js', 'icons/fatin-192.png', 'static/voice.js'):
        assert (ROOT / item).is_file()
    html = (ROOT / 'index.html').read_text()
    for element in ('cloudVoiceConsent', 'voiceWelcome', 'mobileMode', 'mobileDialog', 'voiceRate'):
        assert 'id="' + element + '"' in html


@pytest.fixture
def client():
    import app
    app.app.config['TESTING'] = True
    return app.app.test_client()


def test_voice_requires_consent(client):
    r = client.post('/api/voice', json={'text': 'هلا والله'})
    assert r.status_code == 400
    assert 'الموافقة' in r.json['error']


def test_voice_rejects_long_text(client):
    r = client.post('/api/voice', json={'text': 'ك' * 951, 'voice_consent': True})
    assert r.status_code == 400


def test_voice_endpoint_returns_audio(client, monkeypatch):
    import app

    async def fake_generate(text):
        assert text == 'هلا بك في فطن'
        return b'ID3mock-data'

    monkeypatch.setattr(app, 'synthesize_female_saudi', fake_generate)
    r = client.post('/api/voice', json={'text': 'هلا بك في فطن', 'voice_consent': True})
    assert r.status_code == 200
    assert r.headers['Content-Type'].startswith('audio/mpeg')
    assert r.data == b'ID3mock-data'
    assert r.headers['Cache-Control'] == 'no-store'


def test_root_routes_pwa_assets(client):
    for item in ('voice.js', 'index.html', 'manifest.webmanifest', 'service-worker.js',
                 'icons/fatin-192.png', 'icons/fatin-512.png'):
        r = client.get('/' + item)
        assert r.status_code == 200, item
    assert client.get('/service-worker.js').headers['Service-Worker-Allowed'] == '/'
