#Author: Oz Birdett (oeb0010)
#Date: 12-9-2023
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
import base64
import json
import jwt
import datetime
import sqlite3
import uuid
import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from argon2 import PasswordHasher


private_key = None #Intialize private key

private_key = rsa.generate_private_key( #Generates RSA key
    public_exponent=65537,
    key_size=2048,
)

numbers = private_key.private_numbers() #Numbers of private key
pem = private_key.private_bytes( #Puts numbers into PEM format
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)

ph = PasswordHasher() #Sets ph to instance of PasswordHasher

db_connection = sqlite3.connect("totally_not_my_privateKeys.db") #Connect to database
table_schema = """ 
    CREATE TABLE IF NOT EXISTS keys (
        kid INTEGER PRIMARY KEY AUTOINCREMENT,
        key BLOB NOT NULL,
        exp INTEGER NOT NULL
    )
"""
# Schema for keys table
db_connection.execute(table_schema) #Create table
db_connection.commit() #Commit table

table_schema_users = """
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        email TEXT UNIQUE,
        date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_login TIMESTAMP
    )
"""
#Schema for users table
db_connection.execute(table_schema_users) #Create table
db_connection.commit() #Commit table

table_schema_auth_logs = """
    CREATE TABLE IF NOT EXISTS auth_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        request_ip TEXT NOT NULL,
        request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        user_id INTEGER,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )
"""
#Schema for auth logs table
db_connection.execute(table_schema_auth_logs) #Create table
db_connection.commit() #Commit table

def get_encryption_key(): #Retrievs the encryption key
    key = os.environ.get("ENCRYPTION_KEY")

    if key is None: #Creates new key if there isn't one

        key = os.urandom(32)
        key_str = base64.urlsafe_b64encode(key).decode('utf-8')

        os.environ["ENCRYPTION_KEY"] = key_str

    return base64.urlsafe_b64decode(os.environ["ENCRYPTION_KEY"])

def save_key(key_bytes, exp):
    key = get_encryption_key()

    block_size = 16
    padded_key_bytes = key_bytes + b'\0' * (block_size - len(key_bytes) % block_size)

    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()

    encrypted_key = encryptor.update(padded_key_bytes) + encryptor.finalize()

    with sqlite3.connect("totally_not_my_privateKeys.db") as connection:
        connection.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (encrypted_key, exp))
        connection.commit()

save_key(pem, int(datetime.datetime.utcnow().timestamp())) #Calls save key

def read_key(expired=False):
    current_time = int(datetime.datetime.utcnow().timestamp())
    cursor = db_connection.cursor()
    cursor.execute("SELECT key FROM keys WHERE exp <= ?" if expired else "SELECT key FROM keys WHERE exp > ?", (current_time,))
    row = cursor.fetchone()
    cursor.close()

    if row:
        key = get_encryption_key()
        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_key = decryptor.update(row[0]) + decryptor.finalize()

        return decrypted_key

    return None

def int_to_base64(value): #Converts an integer to base64 encoding
    value_hex = format(value, 'x')
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')

class MyServer(BaseHTTPRequestHandler): #Class to handle HTTP requests
    def do_PUT(self): #PUT Method
        self.send_response(405)
        self.end_headers()
        return

    def do_PATCH(self): #PATCH Method
        self.send_response(405)
        self.end_headers()
        return

    def do_DELETE(self): #DELETE Method
        self.send_response(405)
        self.end_headers()
        return

    def do_HEAD(self): #HEAD Method
        self.send_response(405)
        self.end_headers()
        return
    
    def do_POST(self): #POST Method
        parsed_path = urlparse(self.path) #Checks path of request
        params = parse_qs(parsed_path.query)

        if parsed_path.path == "/auth":
            self.log_auth_request() #Logs authenticaiton request

            headers = {
                "kid": "goodKID"
            }
            token_payload = {
                "user": "username",
                "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
            }

            if 'expired' in params: #If expired
                headers["kid"] = "expiredKID"
                token_payload["exp"] = datetime.datetime.utcnow() - datetime.timedelta(hours=1)
            else:
                headers["kid"] = "goodKID"
                token_payload["exp"] = datetime.datetime.utcnow() + datetime.timedelta(hours=1)

            encoded_jwt = jwt.encode(token_payload, private_key, algorithm="RS256", headers=headers) #Generate a jwt token
            self.send_response(200)
            self.end_headers()
            self.wfile.write(bytes(encoded_jwt, "utf-8"))

        elif parsed_path.path == "/register": #If register
            self.handle_registration() #Calls registration

        else: #If neither, send a 405
            self.send_response(405)
            self.end_headers()
            return

    def handle_registration(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        user_data = json.loads(post_data.decode('utf-8'))

        secure_password = generate_secure_password()
        hashed_password = ph.hash(secure_password)

        try:
            self.save_user(user_data['username'], hashed_password, user_data.get('email'))
            response_data = {"password": secure_password}
            self.send_response(201)
            self.end_headers()
            self.wfile.write(bytes(json.dumps(response_data), "utf-8"))
        except sqlite3.IntegrityError as e:
            # Handle duplicate email address
            self.send_response(400)  # Bad Request
            self.end_headers()
            error_message = {"error": "Email address already exists"}
            self.wfile.write(bytes(json.dumps(error_message), "utf-8"))

    def save_user(self, username, hashed_password, email=None): #Saves users data to the users table
        db_connection.execute("INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)",
                              (username, hashed_password, email))
        db_connection.commit()

    def log_auth_request(self): #Saves authentication request to the auth_logs table
        request_ip = self.client_address[0]
        timestamp = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
        user_id = self.get_user_id()

        db_connection.execute("INSERT INTO auth_logs (request_ip, request_timestamp, user_id) VALUES (?, ?, ?)",
                              (request_ip, timestamp, user_id))
        db_connection.commit()

    def get_user_id(self): #Get user id
        return 1 #Placeholder

def generate_secure_password(): #Generates secure password using UUID library
    return str(uuid.uuid4())

if __name__ == "__main__": #Starts HTTP server
    webServer = HTTPServer(("localhost", 8080), MyServer)
    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass

    webServer.server_close()

'''
Use of ChatGPT in This Assignment
I used ChatGPT to assist with the coding of the server as well as the test suite. I started off by feeding ChatGPT my code from Project 2
of this class and giving it the new requirments for Project 3. From there, I ran the code against the gradebot and told ChatGPT what requirements
the gradebot was looking for. The first error with the gradebot was expecting a password with UUID, so I told ChatGPT and gave me a function that
generated a password with a UUID. I then modified by password generating function to do that. The gradebot could then not find any keys in the database,
so I told ChatGPT and it gave me a save key function that returned the keys to the database. I then added the function to my code. The gradebot then gave
a final error, that the keys were not encrypted, so I told ChatGPT. Which then gave me a modified version of my save and read functions for the keys,
where they were encrypted. I then modified my code and passed all of the gradebot requirements. The last thing I asked ChatGPT to do was make a test suite for my code.
'''
