import pytest
from app import app

def test_jwks_endpoint():
    client = app.test_client()
    response = client.get('/jwks')
    assert response.status_code == 200
    assert 'keys' in response.json

def test_auth_endpoint():
    client = app.test_client()
    response = client.post('/auth')
    assert response.status_code == 200
    assert 'token' in response.json
