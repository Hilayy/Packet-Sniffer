import socket
import json

HOST = 'localhost'
PORT = 12345
ADDR = (HOST, PORT)
class DBClient:
    def __init__(self):
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def send_to_server(self):
        self.client_socket.connect(ADDR)
        data_dict = {'type': 'login', 'username': 'hilay', 'password': 'changeme'}
        json_data = json.dumps(data_dict)
        self.client_socket.send(json_data.encode('utf-8'))
        received_data = self.client_socket.recv(1024).decode('utf-8')
        print(received_data)
        self.client_socket.close()


client = DBClient()
client.send_to_server()



