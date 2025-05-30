from cryptography.hazmat.primitives.asymmetric import x25519
from flask import Flask, request, jsonify
import opaque_common as common
import base64
import os
import secrets
from collections import defaultdict

import logging

logging.basicConfig(level=logging.DEBUG,
                    format="[%(asctime)s][%(name)s][%(levelname)s] %(message)s",
                    datefmt='%Y-%m-%d  %H:%M:%S %a')
app = Flask(__name__)

# 模拟用户数据库
users_db = defaultdict(dict)

# 服务器OPRF密钥 (长期密钥)
SERVER_OPRF_KEY = os.urandom(32)
server_oprf = common.OPRF(SERVER_OPRF_KEY)


# 注册新用户

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

    # 检查用户是否已存在
    if username in users_db:
        return jsonify({"error": "User already exists"}), 400

    # 存储用户公钥和加密信封
    users_db[username] = {
        'public_key': data['public_key'],
        'envelope': data['envelope']
    }
    return jsonify({"status": "success"})


# 登录第一阶段：处理OPRF请求
@app.route('/login/init', methods=['POST'])
def login_init():
    data = request.json
    username = data['username']

    # 检查用户是否存在
    if username not in users_db:
        return jsonify({"error": "User not found"}), 404

    # 获取存储的加密信封
    envelope = base64.b64decode(users_db[username]['envelope'])

    # 处理OPRF请求
    blinded_element = base64.b64decode(data['blinded_element'])
    evaluated_element = server_oprf.blind_evaluate(blinded_element)

    # 生成临时密钥对
    server_private_key = x25519.X25519PrivateKey.generate()
    server_public_key = server_private_key.public_key()

    # 存储会话状态
    session_id = secrets.token_urlsafe(16)
    users_db[username]['session'] = {
        'session_id': session_id,
        'server_private_key': server_private_key,
        'client_public_key': None
    }
    return jsonify({
        "session_id": session_id,
        "evaluated_element": base64.b64encode(evaluated_element).decode(),
        "envelope": base64.b64encode(envelope).decode(),
        "server_public_key": base64.b64encode(
            common.serialize_public_key(server_public_key)
        ).decode()
    })


# 登录第二阶段：密钥交换和认证
@app.route('/login/finish', methods=['POST'])
def login_finish():
    data = request.json
    username = data['username']
    session_id = data['session_id']

    # 验证会话
    if username not in users_db or 'session' not in users_db[username]:
        return jsonify({"error": "Invalid session"}), 400

    session_data = users_db[username]['session']
    if session_data['session_id'] != session_id:
        return jsonify({"error": "Session mismatch"}), 400

    # 获取客户端临时公钥
    client_public_key = common.deserialize_public_key(
        base64.b64decode(data['client_public_key'])
    )
    session_data['client_public_key'] = client_public_key

    # 计算共享密钥
    server_private_key = session_data['server_private_key']
    shared_secret = server_private_key.exchange(client_public_key)

    # 派生会话密钥
    session_key = common.derive_keys(shared_secret, b"OPAQUE_SESSION_KEY")[:32]
    logging.info(f"Session key: {session_key.hex()}")

    # 验证客户端认证消息
    client_auth_msg = base64.b64decode(data['auth_message'])
    # 实际应用中应验证MAC，这里简化

    # 生成服务器认证消息
    server_auth_msg = os.urandom(16)  # 实际应为HMAC

    # 清理会话数据
    del users_db[username]['session']

    return jsonify({
        "status": "success",
        "auth_message": base64.b64encode(server_auth_msg).decode(),
        "session_key": base64.b64encode(session_key).decode()
    })


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, ssl_context='adhoc')