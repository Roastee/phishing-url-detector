import sys
sys.path.insert(0, 'src')
from api.main import app
from fastapi.testclient import TestClient
import json

client = TestClient(app)

# Test /model-info
r = client.get('/model-info')
print('=== /model-info ===')
print(json.dumps(r.json(), indent=2))