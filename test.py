import unittest
import requests
import json
import jwt
import datetime
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from server import save_key, read_key  # Import your script here

class TestMyServer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Initialize private key for testing
        cls.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        cls.private_key_pem = cls.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        # Use cls.private_key_pem in your save_key function
        save_key(cls.private_key_pem, int(datetime.datetime.utcnow().timestamp()))

    def test_server_response(self):
        response = requests.post("http://localhost:8080/auth")
        self.assertEqual(response.status_code, 200, f"Expected 405, but got {response.status_code}")

    def test_registration(self):
        # Assuming the server is running and reachable
        user_data = {
            "username": "test_user",
            "email": "test@example.com"
        }

        response = requests.post("http://localhost:8080/register", data=json.dumps(user_data))
        self.assertEqual(response.status_code, 201, f"Expected 201, but got {response.status_code}")

        response_data = json.loads(response.text)
        self.assertIn("password", response_data)

    def test_jwt_token_generation(self):
        headers = {
            "kid": "goodKID"
        }
        token_payload = {
            "user": "username",
            "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
        }

        encoded_jwt = jwt.encode(token_payload, self.private_key, algorithm="RS256", headers=headers)
        self.assertTrue(encoded_jwt, "Token is empty")  # Expecting a non-empty token

    def test_key_encryption(self):
        exp_time = int(datetime.datetime.utcnow().timestamp())
        decrypted_key = read_key()
        self.assertEqual(None, decrypted_key, "Decrypted key does not match")
if __name__ == '__main__':
    unittest.main()
