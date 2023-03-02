import rsa
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import Crypto
import socket
from threading import Thread

class Client:
    def __init__(self, server_ip, server_port):
        self.s = socket.socket()
        self.s.connect((server_ip, server_port))
    
    def handle_connection(self):
        pass
    
    def initiate_encrypted_data_transfer(self):
        server_public_key = self.s.recv(4096)
        server_public_key = rsa.PublicKey.load_pkcs1(server_public_key)
    
    def create_new_key(self):
        key = get_random_bytes(32)
        self.cipher = AES.new(key, AES.MODE_EAX)
            