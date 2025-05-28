import requests
from phe import paillier

SERVER_URL = 'http://127.0.0.1:5000'


class PIRClient:
    def __init__(self):
        self.public_key, self.private_key = paillier.generate_paillier_keypair()
        requests.post(f'{SERVER_URL}/init', json={'n': str(self.public_key.n)})

    def retrieve_data(self, index):
        query = [self.public_key.encrypt(0) for _ in range(5)]
        query[index] = self.public_key.encrypt(1)

        serialized_query = [{
            'ciphertext': str(q.ciphertext()),
            'exponent': q.exponent
        } for q in query]

        response = requests.post(
            f'{SERVER_URL}/query',
            json={'query': serialized_query}
        ).json()

        encrypted_result = paillier.EncryptedNumber(
            self.public_key,
            int(response['ciphertext']),
            response['exponent']
        )
        return self.private_key.decrypt(encrypted_result)


if __name__ == '__main__':
    client = PIRClient()
    target_index = input("请输入要检索的数据索引 (0-4): ")
    target_index = int(target_index)
    result = client.retrieve_data(target_index)
    print(f"Retrieved data from index {target_index}: {result}")