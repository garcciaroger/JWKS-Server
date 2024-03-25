from flask import Flask, request, jsonify
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import base64
import jwt
import datetime
import sqlite3

app = Flask(__name__)

def create_database():
    conn = sqlite3.connect('totally_not_my_privateKeys.db')
    cursor = conn.cursor()
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS keys(
        kid INTEGER PRIMARY KEY AUTOINCREMENT,
        key BLOB NOT NULL,
        exp INTEGER NOT NULL
    )
    ''')
    conn.commit()
    conn.close()

def save_private_key_to_db(key_bytes, expiry):
    conn = sqlite3.connect('totally_not_my_privateKeys.db')
    cursor = conn.cursor()
    # Ensure expiry is explicitly cast to an integer
    cursor.execute('''
    INSERT INTO keys (key, exp) VALUES (?, ?)
    ''', (key_bytes, int(expiry)))
    conn.commit()
    conn.close()

def get_private_keys_from_db():
    conn = sqlite3.connect('totally_not_my_privateKeys.db')
    cursor = conn.cursor()
    cursor.execute('''
    SELECT kid, key FROM keys WHERE exp > ?
    ''', (int(datetime.datetime.now(datetime.timezone.utc).timestamp()),))
    keys = cursor.fetchall()
    conn.close()
    return keys

def setup_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                                    encryption_algorithm=serialization.NoEncryption())
    save_private_key_to_db(pem, int((datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)).timestamp()))

@app.route('/auth', methods=['POST'])
def auth():
    keys = get_private_keys_from_db()
    if keys:
        kid, private_key_bytes = keys[0]
        decoded_key = serialization.load_pem_private_key(private_key_bytes, password=None, backend=default_backend())
        token_payload = {
            "user": "username",
            "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)
        }
        jwt_headers = {"kid": str(kid)}
        encoded_jwt = jwt.encode(payload=token_payload, key=decoded_key, algorithm="RS256", headers=jwt_headers)
        return jsonify({"token": encoded_jwt}), 200
    return "Private key not found", 404

@app.route('/.well-known/jwks.json', methods=['GET'])
def jwks():
    keys = get_private_keys_from_db()
    jwks_keys = []
    for kid, key_bytes in keys:
        decoded_key = serialization.load_pem_private_key(key_bytes, password=None, backend=default_backend())
        public_key = decoded_key.public_key()
        public_numbers = public_key.public_numbers()
        jwks_keys.append({
            "alg": "RS256",
            "kty": "RSA",
            "use": "sig",
            "kid": str(kid),
            "n": base64.urlsafe_b64encode(public_numbers.n.to_bytes(256, byteorder='big')).decode('utf-8'),
            "e": base64.urlsafe_b64encode(public_numbers.e.to_bytes(3, byteorder='big')).decode('utf-8'),
        })
    return jsonify({"keys": jwks_keys}), 200

if __name__ == '__main__':
    create_database()
    setup_keys()
    # Run the Flask app on the specified host and port
    app.run(host='127.0.0.1', port=8080)
