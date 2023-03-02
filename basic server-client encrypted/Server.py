import rsa
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import Crypto
import socket
from threading import Thread
class Server:
    def __init__(self):
        (self.public_key, self.private_key) = rsa.newkeys(1024)
        self.server_socket = socket.socket()
        self.server_socket.bind(('0.0.0.0', 25565))
        self.wait_for_connection()
        
    
    def wait_for_connection(self):
        self.server_socket.listen(2)
        while True:
            client_socket, client_address = self.server_socket.accept()
            print('Connected to', self.client_address)
            t = Thread(target=self.handle_connection, args=(client_socket,))
            t.start()
            
    
    def handle_connection(self, client_socket):
        self.initiate_encrypted_data_transfer(client_socket)
        while True:
            pass
    
    def initiate_encrypted_data_transfer(self, client_socket):
        client_socket.send(self.public_key.save_pkcs1())
        symetric_key = client_socket.recv(4096)
        
        


server = Server()
