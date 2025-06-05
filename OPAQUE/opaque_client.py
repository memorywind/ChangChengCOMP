import requests
from cryptography.hazmat.primitives import serialization
import hashlib
import opaque_common as common
import base64
import os
from cryptography.hazmat.primitives.asymmetric import x25519
import secrets
import json
import hmac
import hashlib
import logging

logging.basicConfig(level=logging.DEBUG,
                    format="[%(asctime)s][%(name)s][%(levelname)s] %(message)s",
                    datefmt='%Y-%m-%d  %H:%M:%S %a')

SERVER_URL = "http://localhost:5000"

def hash_password(password: bytes):
    return hashlib.sha256(password).digest()

class OPAQUEClient:
    def __init__(self, username, password):
        self.username = username
        self.password = password.encode()
        self.private_key = None
        self.public_key = None
        self.envelope = None
        self.oprf_output = None
        self.session_id = None
        self.session_key = None

    def register(self):
        self.private_key = x25519.X25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()

        self.blinded_element = hash_password(self.password)

        response = requests.post(
            f"{SERVER_URL}/register/init",
            json={
                "username": self.username,
                "blinded_element": base64.b64encode(self.blinded_element).decode()
            }
        ).json()

        if "error" in response:
            raise Exception(response["error"])

        evaluated_element = base64.b64decode(response["evaluated_element"])
        self.oprf_output = evaluated_element

        key_material = common.derive_keys(self.oprf_output, b"OPAQUE_ENVELOPE_KEY")
        encryption_key = key_material[:32]

        private_key_bytes = self.private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )
        public_key_bytes = common.serialize_public_key(self.public_key)
        envelope_data = private_key_bytes + public_key_bytes
        self.envelope = common.encrypt_aes_gcm(encryption_key, envelope_data)

        response = requests.post(
            f"{SERVER_URL}/register",
            json={
                "username": self.username,
                "public_key": base64.b64encode(public_key_bytes).decode(),
                "envelope": base64.b64encode(self.envelope).decode()
            }
        )
        return response.json()

    def login(self):
        blinded_element = hash_password(self.password)
        response = requests.post(
            f"{SERVER_URL}/login/init",
            json={
                "username": self.username,
                "blinded_element": base64.b64encode(blinded_element).decode()
            }
        ).json()

        if "error" in response:
            raise Exception(response["error"])

        self.session_id = response["session_id"]
        evaluated_element = base64.b64decode(response["evaluated_element"])
        self.oprf_output = evaluated_element

        encrypted_envelope = base64.b64decode(response["envelope"])
        key_material = common.derive_keys(self.oprf_output, b"OPAQUE_ENVELOPE_KEY")
        decryption_key = key_material[:32]

        logging.info(f'Session ID:{self.session_id}')
        logging.info(f'Received evaluated_element:{evaluated_element.hex()}')
        logging.info(f'Received envelope:{encrypted_envelope.hex()}')

        try:
            envelope_data = common.decrypt_aes_gcm(decryption_key, encrypted_envelope)
        except Exception as e:
            raise Exception("Failed to decrypt envelope: " + str(e))

        private_key_bytes = envelope_data[:32]
        self.private_key = x25519.X25519PrivateKey.from_private_bytes(private_key_bytes)

        server_public_key = common.deserialize_public_key(
            base64.b64decode(response["server_public_key"])
        )

        client_private_key = x25519.X25519PrivateKey.generate()
        client_public_key = client_private_key.public_key()
        shared_secret = client_private_key.exchange(server_public_key)
        logging.info(f'Shared secret: {shared_secret.hex()}')
        session_key = common.derive_keys(shared_secret, b"OPAQUE_SESSION_KEY")[:32]
        self.session_key = session_key

        auth_message = os.urandom(16)

        response = requests.post(
            f"{SERVER_URL}/login/finish",
            json={
                "username": self.username,
                "session_id": self.session_id,
                "client_public_key": base64.b64encode(
                    common.serialize_public_key(client_public_key)
                ).decode(),
                "auth_message": base64.b64encode(auth_message).decode()
            }
        ).json()

        if response.get("status") != "success":
            raise Exception("Authentication failed")

        ciphertext = base64.b64decode(response["ciphertext"])
        logging.info(f"Received ciphertext: {ciphertext.hex()}")
        received_hmac = base64.b64decode(response["auth_message"])
        logging.info(f"Received HMAC: {received_hmac.hex()}")
        calc_hmac = hmac.new(session_key, ciphertext, hashlib.sha256).digest()
        if not hmac.compare_digest(received_hmac, calc_hmac):
            raise Exception("HMAC verification failed")

        command = common.decrypt_aes_gcm(session_key, ciphertext)
        logging.info(f"Received secure command: {command.decode()}")
        return session_key


def main():
    username = input("Enter username: ")
    password = input("Enter password: ")
    action = input("Register or Login? (r/l): ").strip().lower()

    client = OPAQUEClient(username, password)

    if action == 'r':
        logging.info(f"Registering user...")
        result = client.register()
        logging.info(f"Registration result: {result['status']}")
    elif action == 'l':
        logging.info("Logging in...")
        try:
            session_key = client.login()
            logging.info("Authentication successful!")
            logging.info(f"Session key: {session_key.hex()}")
        except Exception as e:
            print(f"Authentication failed: {str(e)}")
    else:
        print("Invalid action")

if __name__ == '__main__':
    main()