import socket
import json
from DB import DB
# Create a socket object
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Get the local machine name
HOST = 'localhost'
PORT = 12345
ADDR = (HOST, PORT)


class DBServer:
    def __init__(self):
        self.db = DB()
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind(ADDR)
        self.server_socket.listen(1)
        print(f"Server listening on {HOST}:{PORT}")
        while True:
            # Wait for a connection
            client_socket, addr = self.server_socket.accept()
            print(f"Got connection from {addr}")
            json_data = client_socket.recv(1024).decode('utf-8')
            data_dict = json.loads(json_data)
            self.handle_client_request(data_dict, client_socket)

    def handle_client_request(self, dict, client_socket):
        answer = ''
        if dict['type'] == 'login':
            answer = self.handle_login(dict)
        if dict['type'] == 'signup':
            answer = self.handle_signup(dict)
        client_socket.send(answer.encode('utf-8'))

    def handle_login(self, dict):
        result = self.db.username_exists(username=dict['username'])
        if result is None:
            return 'X'
        else:
            if self.db.password_matches(result, dict['password']):

                return 'V'
        return 'X'

    def handle_signup(self, dict):
        result = self.db.username_exists(username=dict['username'])
        if result is not None:
            return 'X'
        user_dict = {'username': dict['username'], 'password': dict['password']}
        self.db.add_user(user_dict)
        return 'V'




server = DBServer()
