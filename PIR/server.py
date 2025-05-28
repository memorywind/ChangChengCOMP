from flask import Flask, request, jsonify
from phe import paillier
import json

app = Flask(__name__)
database = [10, 20, 30, 40, 50]
public_key = None


@app.route('/init', methods=['POST'])
def init_key():
    global public_key
    key_data = request.json
    public_key = paillier.PaillierPublicKey(n=int(key_data['n']))
    return jsonify({'status': 'public key received'})


@app.route('/query', methods=['POST'])
def process_query():
    if not public_key:
        return jsonify({'error': 'Public key not initialized'}), 400

    encrypted_query = request.json['query']

    # 修正后的加密数据转换
    encrypted_values = [
        paillier.EncryptedNumber(public_key, int(item['ciphertext']))
        for item in encrypted_query
    ]

    # 同态计算
    encrypted_result = sum(q * data for q, data in zip(encrypted_values, database))

    response = {
        'ciphertext': str(encrypted_result.ciphertext()),
        'exponent': encrypted_result.exponent
    }
    return jsonify(response)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)