from flask import Flask, jsonify, request
import jwt
import datetime
import sqlite3
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

app = Flask(__name__)

DB_NAME = 'privateKeys.db'

def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS keys
                      (kid INTEGER PRIMARY KEY AUTOINCREMENT,
                       key TEXT NOT NULL,
                       exp INTEGER NOT NULL)''')
    conn.commit()
    conn.close()

def save_key(serialized_key, expiration_timestamp):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('INSERT INTO keys (key, exp) VALUES (?, ?)', (serialized_key, expiration_timestamp))
    conn.commit()
    conn.close()

def generate_rsa_key():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    return private_pem

def get_db_key(expired=False):
    now = int(datetime.datetime.now().timestamp())
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        if expired:
            cursor.execute('SELECT key FROM keys WHERE exp <= ? ORDER BY exp DESC LIMIT 1', (now,))
        else:
            cursor.execute('SELECT key FROM keys WHERE exp > ? ORDER BY exp ASC LIMIT 1', (now,))
        key_row = cursor.fetchone()
    if key_row:
        return key_row[0]
    return None

@app.route('/auth', methods=['POST'])
def authenticate():
    expired = request.args.get('expired', 'false').lower() == 'true'
    private_key_pem = get_db_key(expired=expired)
    if not private_key_pem:
        return jsonify({"error": "No suitable key found."}), 404
    
    expiry_time = datetime.datetime.utcnow() + (datetime.timedelta(minutes=-5) if expired else datetime.timedelta(minutes=5))
    token = jwt.encode(
        {"exp": expiry_time},
        private_key_pem,
        algorithm="RS256"
    )
    
    return jsonify(token=token)

@app.route('/jwks', methods=['GET'])
def jwks():
    jwks = {
        "keys": [
            {
                "kty": "RSA",
                "use": "sig",
                "kid": key_id,
                "alg": "RS256",
                "n": "public_key_part_n",
                "e": "public_key_part_e"
            }
        ]
    }
    return jsonify(jwks)

if __name__ == '__main__':
    init_db()
    private_pem = generate_rsa_key()
    save_key(private_pem.decode(), int((datetime.datetime.now() + datetime.timedelta(minutes=10)).timestamp()))  # Expires in future
    save_key(private_pem.decode(), int((datetime.datetime.now() - datetime.timedelta(minutes=10)).timestamp()))  # Already expired
    app.run(debug=True, port=8080)
