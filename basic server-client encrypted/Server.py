import rsa
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
#import unpad
from Crypto.Util.Padding import pad, unpad
import Crypto
import socket
from threading import Thread
import time
import math
class Server:
    def __init__(self):
        """This function initializes the server and waits for a connection
        """
        (self.public_key, self.private_key) = rsa.newkeys(1024)
        self.server_socket_tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket_tcp.bind(('0.0.0.0', 25565))

        self.wait_for_connection()
    
    def wait_for_connection(self):
        """This function waits for a connection and then starts a thread to handle the connection
        """
        self.server_socket_tcp.listen(2)
        while True:
            client_socket, client_address = self.server_socket_tcp.accept()
            print('Connected to', client_address)
            t = Thread(target=self.handle_connection, args=(client_socket, client_address))
            t.start()
    
    def handle_connection(self, client_socket, client_address):
        """This function handles the connection with the client

        Args:
            client_socket (socket): The socket used to communicate with the client
            client_address (tuple): The address of the client
        """
        self.initiate_encrypted_data_transfer(client_socket)
        while True:
            choice = input("What do you want to do? (1) Freeze (2) Unfreeze (3) Exit: ")
            if choice == '1':
                self.freeze_PC(client_socket)
            
    def freeze_PC(self, client_socket):
        """This function freezes the PC of the client

        Args:
            client_socket (socket): The socket used to communicate with the client
        """
        self.send_data_tcp("FREEZE", client_socket)
        
        confirmation = self.recv_data_tcp(client_socket).decode()
        while confirmation != "FROZEN":
            self.send_data_tcp("FREEZE", client_socket)
            confirmation = self.recv_data_tcp(client_socket).decode()
            
    def initiate_encrypted_data_transfer(self, client_socket):
        """This function initiates the encrypted data transfer with the client

        Args:
            client_socket (socket): The socket used to communicate with the client
        """
        client_socket.send(self.public_key.save_pkcs1())
        data = client_socket.recv(128)
        
        data = rsa.decrypt(data, self.private_key)
        
        self.key = data[:32]
        self.iv = data[32:]
        self.cipher = AES.new(self.key, AES.MODE_CBC, iv=self.iv)
    
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

    def decrypt_data(self, data):
        """This function decrypts the data received from the client
        
        Args:
            data (bytes): The data received from the client

        Returns:
            bytes: The decrypted data, or False if the decryption failed
        """
        try:
            msg = self.cipher.decrypt(data)
            msg = unpad(msg, AES.block_size)
        except:
            msg = False
        return msg
    
    def recv_data_tcp(self, client_socket):
        """This function receives data from the client

        Args:
            client_socket (socket): The socket used to communicate with the client

        Returns:
            bytes: The decrypted data, or False if the decryption failed
        """
        full_data = b''

        data = client_socket.recv(4096)
        while data != b'END':
            full_data += data
            data = client_socket.recv(4096)

        return self.decrypt_data(full_data)
    
    def send_data_tcp(self, msg, client_socket):
        ciphertext = self.cipher.encrypt(pad(msg.encode(), AES.block_size))
        packets = self.split_data(ciphertext)
        for packet in packets:
            client_socket.send(packet)
    
    def send_data_udp(self, msg, client_socket, client_address):
        """This function sends data to the client using UDP.

        Args:
            msg (str): The message to send
            client_socket (socket): The socket used to communicate with the client
            client_address (tuple): The address of the client
        """
        ciphertext = self.cipher.encrypt(pad(msg.encode(), AES.block_size))
        packets = self.split_data(ciphertext)
        for packet in packets:
            client_socket.sendto(packet, client_address)
    
    def recv_data_udp(self, client_socket):
        """This function receives data from the client using UDP.

        Args:
            client_socket (socket): The socket used to communicate with the client

        Returns:
            bytes: The decrypted data, or False if the decryption failed
        """
        full_data = b''
        data, addr = client_socket.recvfrom(4096)
        while data != b'END':
            full_data += data
            data, addr = client_socket.recvfrom(4096)
        return self.decrypt_data(full_data)

server = Server()
