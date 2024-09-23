from flask import Flask, jsonify, request
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from datetime import datetime, timedelta
import random

app = Flask(__name__)

# Key store (In-memory for simplicity)
keys = {}

# Function to generate RSA keys
def generate_rsa_keypair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    
    # Serialize public key in PEM format
    pub_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private_key, pub_pem.decode('utf-8')

# Add a new key with expiry
def add_key(kid, expiry_hours=24):
    private_key, public_key = generate_rsa_keypair()
    expiry = datetime.utcnow() + timedelta(hours=expiry_hours)
    keys[kid] = {
        'private_key': private_key,
        'public_key': public_key,
        'expiry': expiry
    }

# JWKS endpoint
@app.route('/jwks', methods=['GET'])
def jwks():
    jwks_keys = []
    for kid, key_info in keys.items():
        if key_info['expiry'] > datetime.utcnow():
            jwks_keys.append({
                'kty': 'RSA',
                'kid': kid,
                'use': 'sig',
                'alg': 'RS256',
                'n': key_info['public_key']
            })
    return jsonify({'keys': jwks_keys})

# /auth endpoint for JWT issuance
@app.route('/auth', methods=['POST'])
def auth():
    expired = request.args.get('expired', 'false').lower() == 'true'
    
    if expired:
        # Find an expired key
        expired_keys = {kid: key_info for kid, key_info in keys.items() if key_info['expiry'] <= datetime.utcnow()}
        if not expired_keys:
            return jsonify({'error': 'No expired keys available'}), 400
        kid, key_info = random.choice(list(expired_keys.items()))
    else:
        # Find an unexpired key
        unexpired_keys = {kid: key_info for kid, key_info in keys.items() if key_info['expiry'] > datetime.utcnow()}
        if not unexpired_keys:
            return jsonify({'error': 'No active keys available'}), 400
        kid, key_info = random.choice(list(unexpired_keys.items()))
    
    payload = {
        'sub': 'mock_user',
        'exp': datetime.utcnow() + timedelta(hours=1),
        'iat': datetime.utcnow()
    }
    token = jwt.encode(payload, key_info['private_key'], algorithm='RS256', headers={'kid': kid})
    
    return jsonify({'token': token})

# Add some initial keys (with different expiry times)
add_key('key1', expiry_hours=1)  # Expires soon
add_key('key2', expiry_hours=24) # Valid for 24 hours

if __name__ == '__main__':
    app.run(port=8080)
