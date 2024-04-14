from flask import Flask, request, jsonify
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64
import jwt
import datetime
import sqlite3
import os
import uuid
import argon2
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)
limiter = Limiter(app, default_limits=["10 per second"])

# Encryption Key
encryption_key = os.environ.get("NOT_MY_KEY", "default_encryption_key")

def derive_key(encryption_key):
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(encryption_key.encode())

def encrypt_private_key(key_bytes, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(key_bytes) + padder.finalize()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return iv + encrypted_data

def decrypt_private_key(encrypted_data, key):
    iv = encrypted_data[:16]
    encrypted_data = encrypted_data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()
    return unpadded_data

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
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        email TEXT UNIQUE,
        date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_login TIMESTAMP      
    )
    ''')
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS auth_logs(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        request_ip TEXT NOT NULL,
        request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        user_id INTEGER,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )
    ''')
    conn.commit()
    conn.close()

def save_private_key_to_db(key_bytes, expiry):
    conn = sqlite3.connect('totally_not_my_privateKeys.db')
    cursor = conn.cursor()
    derived_key = derive_key(encryption_key)
    encrypted_key = encrypt_private_key(key_bytes, derived_key)
    cursor.execute('''
    INSERT INTO keys (key, exp) VALUES (?, ?)
    ''', (encrypted_key, int(expiry)))
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

def register_user(username, email):
    password = str(uuid.uuid4())
    password_hash = argon2.PasswordHasher().hash(password)
    conn = sqlite3.connect('totally_not_my_privateKeys.db')
    cursor = conn.cursor()
    cursor.execute('''
    INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)
    ''', (username, password_hash, email))
    conn.commit()
    conn.close()
    return password

def log_auth_request(request_ip, user_id):
    try:
        conn = sqlite3.connect('totally_not_my_privateKeys.db')
        cursor = conn.cursor()
        cursor.execute('''
        INSERT INTO auth_logs (request_ip, user_id) VALUES (?, ?)
        ''', (request_ip, user_id))
        conn.commit()
    except Exception as e:
        print("Error logging auth request:", e)  # Add this debug print
    finally:
        conn.close()

def setup_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                                    encryption_algorithm=serialization.NoEncryption())
    save_private_key_to_db(pem, int((datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)).timestamp()))
# Call setup_keys() here to ensure it's executed after the app is initialized
setup_keys()

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    email = data.get('email')
    if not username or not email:
        return jsonify({"error": "Username and email are required"}), 400
    try:
        password = register_user(username, email)
        return jsonify({"password": password}), 201
    except sqlite3.IntegrityError:
        return jsonify({"error": "Username or email already exists"}), 400

@app.route('/auth', methods=['POST'])
@limiter.limit("10/second")
def auth():
    try:
        keys = get_private_keys_from_db()
        if keys:
            kid, encrypted_private_key = keys[0]
            derived_key = derive_key(encryption_key)
            private_key = decrypt_private_key(encrypted_private_key, derived_key)
            decoded_key = serialization.load_pem_private_key(private_key, password=None, backend=default_backend())
            token_payload = {
                "user": "username",
                "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)
            }
            jwt_headers = {"kid": str(kid)}
            encoded_jwt = jwt.encode(payload=token_payload, key=decoded_key, algorithm="RS256", headers=jwt_headers)
            user_id = get_user_id_by_username(token_payload["user"])
            # Log the authentication request
            log_auth_request(request.remote_addr, user_id)        
            return jsonify({"token": encoded_jwt}), 200
        return "Private key not found", 404
    except Exception as e:
        print("Error in auth endpoint:", e)  # Add this debug print
        return "Internal server error", 500



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
    app.run(host='127.0.0.1', port=8080, debug=True)
