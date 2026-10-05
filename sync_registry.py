import json
from pathlib import Path
root=Path(__file__).resolve().parent
registry=json.loads((root/'registry.json').read_text())
for folder in ('static','extension'):
    p=root/folder/'identity.js'
    s=p.read_text();start=s.index('const FATIN_REGISTRY = ');end=s.index(';',start)
    s=s[:start]+'const FATIN_REGISTRY = '+json.dumps(registry,ensure_ascii=False)+s[end:]
    p.write_text(s)
for filename in ('index.html','style.css','app.js','identity.js'):
    (root/filename).write_bytes((root/'static'/filename).read_bytes())
print('Updated registry and root frontend assets')
