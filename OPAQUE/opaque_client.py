import requests
from cryptography.hazmat.primitives import serialization
import hashlib
import opaque_common as common
import base64
import os
from cryptography.hazmat.primitives.asymmetric import x25519
import secrets
import json
import logging

logging.basicConfig(level=logging.DEBUG,
                    format="[%(asctime)s][%(name)s][%(levelname)s] %(message)s",
                    datefmt='%Y-%m-%d  %H:%M:%S %a')

SERVER_URL = "https://localhost:5000"

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

    def register(self):
        # 生成长期密钥对
        self.private_key = x25519.X25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()

        # 1. 盲化密码（这里先用随机数代替，应使用真实密码 OPRF 实现）
        self.blinded_element = hash_password(self.password)

        # 2. 发送 blinded_element 到服务器获得 evaluated_element
        response = requests.post(
            f"{SERVER_URL}/register/init",
            json={
                "username": self.username,
                "blinded_element": base64.b64encode(self.blinded_element).decode()
            },
            verify=False
        ).json()

        if "error" in response:
            raise Exception(response["error"])

        evaluated_element = base64.b64decode(response["evaluated_element"])
        self.oprf_output = evaluated_element  # 实际应反盲化

        # 3. 派生 envelope 密钥并加密
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

        # 4. 发送注册请求
        response = requests.post(
            f"{SERVER_URL}/register",
            json={
                "username": self.username,
                "public_key": base64.b64encode(public_key_bytes).decode(),
                "envelope": base64.b64encode(self.envelope).decode()
            },
            verify=False
        )
        return response.json()

    def login(self):
        """用户登录流程"""
        # 第一阶段：获取OPRF响应和信封
        blinded_element = hash_password(self.password)
        response = requests.post(
            f"{SERVER_URL}/login/init",
            json={
                "username": self.username,
                "blinded_element": base64.b64encode(blinded_element).decode()
            },
            verify=False
        ).json()

        if "error" in response:
            raise Exception(response["error"])

        # 保存会话ID
        self.session_id = response["session_id"]

        # 处理OPRF响应
        evaluated_element = base64.b64decode(response["evaluated_element"])
        self.oprf_output = evaluated_element  # 实际应反盲化

        # 获取加密信封
        encrypted_envelope = base64.b64decode(response["envelope"])

        # 派生解密密钥
        key_material = common.derive_keys(self.oprf_output, b"OPAQUE_ENVELOPE_KEY")
        decryption_key = key_material[:32]
        mac_key = key_material[32:48]
        logging.info("[DEBUG] Session ID:", self.session_id)
        logging.info("[DEBUG] Received evaluated_element:", evaluated_element.hex())
        logging.info("[DEBUG] Encrypted envelope:", encrypted_envelope.hex())
        # 解密信封获取私钥
        try:
            envelope_data = common.decrypt_aes_gcm(decryption_key, encrypted_envelope)
        except Exception as e:
            raise Exception("Failed to decrypt envelope: " + str(e))
        logging.info("[DEBUG] Decrypted envelope length:", len(envelope_data))

        private_key_bytes = envelope_data[:32]
        self.private_key = x25519.X25519PrivateKey.from_private_bytes(private_key_bytes)

        # 获取服务器临时公钥
        server_public_key = common.deserialize_public_key(
            base64.b64decode(response["server_public_key"])
        )

        # 生成客户端临时密钥对
        client_private_key = x25519.X25519PrivateKey.generate()
        client_public_key = client_private_key.public_key()

        # 计算共享密钥
        shared_secret = client_private_key.exchange(server_public_key)

        # 派生会话密钥
        session_key = common.derive_keys(shared_secret, b"OPAQUE_SESSION_KEY")[:32]

        # 生成认证消息
        auth_message = os.urandom(16)  # 实际应为HMAC

        # 发送登录完成请求
        response = requests.post(
            f"{SERVER_URL}/login/finish",
            json={
                "username": self.username,
                "session_id": self.session_id,
                "client_public_key": base64.b64encode(
                    common.serialize_public_key(client_public_key)
                ).decode(),
                "auth_message": base64.b64encode(auth_message).decode()
            },
            verify=False
        ).json()

        if response.get("status") != "success":
            raise Exception("Authentication failed")

        # 验证服务器认证消息
        server_auth_msg = base64.b64decode(response["auth_message"])
        # 实际应验证MAC

        # 返回会话密钥
        return base64.b64decode(response["session_key"])


def main():
    # 用户交互
    username = input("Enter username: ")
    password = input("Enter password: ")
    action = input("Register or Login? (r/l): ").strip().lower()

    client = OPAQUEClient(username, password)

    if action == 'r':
        print("Registering user...")
        result = client.register()
        print("Registration result:", result)
    elif action == 'l':
        print("Logging in...")
        try:
            session_key = client.login()
            logging.info("\nAuthentication successful!")
            logging.info(f"Session key: {session_key.hex()}")
        except Exception as e:
            print(f"Authentication failed: {str(e)}")
    else:
        print("Invalid action")


if __name__ == '__main__':
    main()