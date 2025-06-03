from cryptography.hazmat.primitives.asymmetric import x25519
from flask import Flask, request, jsonify
import opaque_common as common
import base64
import os
import secrets
from collections import defaultdict
import hmac
import hashlib
import logging

logging.basicConfig(level=logging.DEBUG,
                    format="[%(asctime)s][%(name)s][%(levelname)s] %(message)s",
                    datefmt='%Y-%m-%d  %H:%M:%S %a')
app = Flask(__name__)

users_db = defaultdict(dict)
SERVER_OPRF_KEY = os.urandom(32)
server_oprf = common.OPRF(SERVER_OPRF_KEY)

@app.route('/register/init', methods=['POST'])
def register_init():
    data = request.json
    username = data['username']

    if username in users_db:
        return jsonify({"error": "User already exists"}), 400

    blinded_element = base64.b64decode(data['blinded_element'])
    evaluated_element = server_oprf.blind_evaluate(blinded_element)

    return jsonify({
        "evaluated_element": base64.b64encode(evaluated_element).decode()
    })

@app.route('/register', methods=['POST'])
def register_user():
    data = request.json
    username = data['username']

    if username in users_db:
        return jsonify({"error": "User already exists"}), 400

    users_db[username] = {
        'public_key': data['public_key'],
        'envelope': data['envelope']
    }
    return jsonify({"status": "success"})

@app.route('/login/init', methods=['POST'])
def login_init():
    data = request.json
    username = data['username']

    if username not in users_db:
        return jsonify({"error": "User not found"}), 404

    envelope = base64.b64decode(users_db[username]['envelope'])
    blinded_element = base64.b64decode(data['blinded_element'])
    evaluated_element = server_oprf.blind_evaluate(blinded_element)

    server_private_key = x25519.X25519PrivateKey.generate()
    server_public_key = server_private_key.public_key()

    session_id = secrets.token_urlsafe(16)
    users_db[username]['session'] = {
        'session_id': session_id,
        'server_private_key': server_private_key,
        'client_public_key': None,
        'shared_secret': None
    }
    return jsonify({
        "session_id": session_id,
        "evaluated_element": base64.b64encode(evaluated_element).decode(),
        "envelope": base64.b64encode(envelope).decode(),
        "server_public_key": base64.b64encode(
            common.serialize_public_key(server_public_key)
        ).decode()
    })

@app.route('/login/finish', methods=['POST'])
def login_finish():
    data = request.json
    username = data['username']
    session_id = data['session_id']

    if username not in users_db or 'session' not in users_db[username]:
        return jsonify({"error": "Invalid session"}), 400

    session_data = users_db[username]['session']
    if session_data['session_id'] != session_id:
        return jsonify({"error": "Session mismatch"}), 400

    client_public_key = common.deserialize_public_key(
        base64.b64decode(data['client_public_key'])
    )
    session_data['client_public_key'] = client_public_key

    server_private_key = session_data['server_private_key']
    shared_secret = server_private_key.exchange(client_public_key)
    session_data['shared_secret'] = shared_secret

    session_key = common.derive_keys(shared_secret, b"OPAQUE_SESSION_KEY")[:32]
    logging.info(f"Session key: {session_key.hex()}")

    command = b"run update"
    ciphertext = common.encrypt_aes_gcm(session_key, command)
    auth_message = hmac.new(session_key, ciphertext, hashlib.sha256).digest()

    del users_db[username]['session']

    return jsonify({
        "status": "success",
        "auth_message": base64.b64encode(auth_message).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode()
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)