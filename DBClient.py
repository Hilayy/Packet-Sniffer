import socket
import json
import hashlib

HOST = 'localhost'
PORT = 12345
ADDR = (HOST, PORT)


class DBClient:
    def __init__(self):
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def ask_login(self, username, password):
        password = self.hash_password(password)
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Create a new socket instance
        try:
            self.client_socket.connect(ADDR)
            data_dict = {'type': 'login', 'username': username, 'password': password}
            json_data = json.dumps(data_dict)
            self.client_socket.send(json_data.encode('utf-8'))
            received_data = self.client_socket.recv(1024).decode('utf-8')
            return received_data == 'V'
        finally:
            self.client_socket.close()

    def ask_signup(self, username, password):
        password = self.hash_password(password)
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.client_socket.connect(ADDR)
            data_dict = {'type': 'signup', 'username': username, 'password': password}
            json_data = json.dumps(data_dict)
            self.client_socket.send(json_data.encode('utf-8'))
            received_data = self.client_socket.recv(1024).decode('utf-8')
            return received_data == 'V'

        finally:
            self.client_socket.close()

    def hash_password(self, password):
        sha256_hash = hashlib.sha256()
        sha256_hash.update(password.encode('utf-8'))
        hashed_password = sha256_hash.hexdigest()
        return hashed_password
