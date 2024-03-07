from flask import Flask, jsonify, request
import jwt
import datetime
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

app = Flask(__name__)

# For demonstration purposes, generating a new RSA key pair on startup.
# In a real application, you'd likely load this from secure storage.
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)

# Extracting the public key
public_key = private_key.public_key()

# Convert the RSA keys to PEM format for use with PyJWT
private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Dummy Key ID for demonstration
key_id = "mykey1"


@app.route('/auth', methods=['POST'])
def authenticate():
    expired = request.args.get('expired', 'false').lower() == 'true'
    expiry_time = datetime.datetime.utcnow() + (datetime.timedelta(minutes=-5) if expired else datetime.timedelta(minutes=5))
    
    token = jwt.encode(
        {"exp": expiry_time},
        private_pem,
        algorithm="RS256",
        headers={"kid": key_id}
    )
    
    return jsonify(token=token)


@app.route('/jwks', methods=['GET'])
def jwks():
    # For simplicity, returning a static key. In a real app, query your key storage.
    # Convert the RSA public key to JWKS format
    # Note: You'll need to convert the RSA public key to the specific values needed by JWKS
    jwks = {
        "keys": [
            {
                "kty": "RSA",
                "use": "sig",
                "kid": key_id,
                "alg": "RS256",
                # These values need to be actual RSA public key components (n and e) in base64 format
                "n": "public_key_part_n",
                "e": "public_key_part_e"
            }
        ]
    }
    return jsonify(jwks)

if __name__ == '__main__':
    app.run(debug=True, port=8080)
