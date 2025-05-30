from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import ec, x25519
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import os
import secrets
import base64


# OPRF简化实现 (实际应使用安全库如libopaque)
class OPRF:
    def __init__(self, key=None):
        if key is None:
            key = os.urandom(32)
        self.key = key

    def evaluate(self, input_data):
        """服务器端OPRF计算"""
        h = hmac.HMAC(self.key, hashes.SHA256())
        h.update(input_data)
        return h.finalize()

    def blind_evaluate(self, blinded_element):
        """服务器对盲化元素计算"""
        return self.evaluate(blinded_element)


# 密钥派生函数
def derive_keys(shared_secret, info, salt=None, length=64):
    hkdf = HKDF(
        algorithm=hashes.SHA512(),
        length=length,
        salt=salt,
        info=info,
        backend=default_backend()
    )
    return hkdf.derive(shared_secret)


# AES-GCM加密
def encrypt_aes_gcm(key, plaintext, associated_data=None):
    nonce = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    if associated_data:
        encryptor.authenticate_additional_data(associated_data)
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return nonce + ciphertext + encryptor.tag


# AES-GCM解密
def decrypt_aes_gcm(key, ciphertext, associated_data=None):
    nonce = ciphertext[:12]
    tag = ciphertext[-16:]
    ciphertext = ciphertext[12:-16]

    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    if associated_data:
        decryptor.authenticate_additional_data(associated_data)
    return decryptor.update(ciphertext) + decryptor.finalize()


# 序列化/反序列化密钥
def serialize_public_key(public_key):
    if isinstance(public_key, x25519.X25519PublicKey):
        return public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
    return None


def deserialize_public_key(public_bytes):
    return x25519.X25519PublicKey.from_public_bytes(public_bytes)