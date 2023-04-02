import rsa
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import Crypto
import socket
from threading import Thread
import math
import time
import Freeze
class Client:
    def __init__(self, server_ip, server_port):
        """This function initializes the client and connects to the server.

        Args:
            server_ip (string): The IP address of the server.
            server_port (int): The port of the server.
        """
        self.server_ip = server_ip
        self.server_port = server_port
        self.s_tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s_tcp.connect((server_ip, server_port))
        self.freezer = Freeze.Freezer()
        self.handle_connection()

    def handle_connection(self):
        """This function handles the connection to the server.
        """
        self.initiate_encrypted_data_transfer()
        
        while True:
            command = self.recv_data_tcp()
            if command == b'FREEZE':
                self.freezer.freeze()
                self.send_data_tcp("FROZEN")

            

    def initiate_encrypted_data_transfer(self):
        """This function initiates the encrypted data transfer.
        """
        server_public_key = self.s_tcp.recv(4096)
        server_public_key = rsa.PublicKey.load_pkcs1(server_public_key)
        self.create_and_send_key(server_public_key)

    def create_and_send_key(self, server_public_key):
        """This function creates an AES-256 key and sends it to the server.

        Args:
            server_public_key (rsa.PublicKey): The public key of the server.
        """
        self.key = get_random_bytes(32)
        self.cipher = AES.new(self.key, AES.MODE_CBC)
        encrypted_key = rsa.encrypt(b''.join([self.key, self.cipher.iv]), server_public_key)
        self.s_tcp.send(encrypted_key)
    
    def split_data(self, encrypted_msg):
        """This function splits the encrypted message into packets of 4096 bytes.
        It also adds a b'END' packet at the end.

        Args:
            encrypted_msg (bytes): The encrypted message.
        
        Returns:
            list: A list of packets.
        """
        packets = []

        for i in range(0, len(encrypted_msg)-4096, 4096):
            packets.append(encrypted_msg[i:i+4096])

        data = encrypted_msg[len(encrypted_msg)- len(encrypted_msg)%4096:]
        if len(data) > 0:
            packets.append(data)

        packets.append(b"END")

        return packets
    
    def send_data_tcp(self, msg):
        """This function encrypts the message and sends it to the server.

        Args:
            msg (string): The message to send.
        """
        ciphertext = self.cipher.encrypt(pad(msg.encode(), AES.block_size))
        packets = self.split_data(ciphertext)
        for packet in packets:
            self.s_tcp.send(packet)
        
    
    def decrypt_data(self, data):
        """This function decrypts the data using the AES-256 key.

        Args:
            data (bytes): The data to decrypt.

        Returns:
            bytes: The decrypted data, or False if the decryption failed
        """
        try:
            print(data)
            msg = self.cipher.decrypt(data)
            msg = unpad(msg, AES.block_size)
        except:
            msg = False
        return msg

    def recv_data_tcp(self):
        """This function receives data from the server.
        """
        full_data = b''
        data = self.s_tcp.recv(4096)
        while data != b'END':
            full_data += data
            data = self.s_tcp.recv(4096)
        
        return self.decrypt_data(full_data)
    
    def send_data_udp(self, msg):
        """This function encrypts the message and sends it to the server using UDP.

        Args:
            msg (string): The message to send.
        """
        encrypted_msg = self.cipher.encrypt(pad(msg.encode(), AES.block_size))
        packets = self.split_data(encrypted_msg)
        for packet in packets:
            self.s_tcp.sendto(packet, (self.server_ip, self.server_port))
    
    def recv_data_udp(self):
        """This function receives data from the server using UDP and decrypts it.
        """
        full_data = b''
        data, addr = self.s_tcp.recvfrom(4096)
        while data != b'END':
            full_data += data
            data, addr = self.s_tcp.recvfrom(4096)
        
        return self.decrypt_data(full_data)
        

client = Client('127.0.0.1', 25565)
