"""This module contains the basic functions used by the client and server.
It contains multiple classes and functions:
    - Useful_Functions: This class contains multiple useful functions.
    - Cipher: This class is used to encrypt and decrypt messages using AES-EAX mode.
    - Encrypted_TCP_Socket: This class is used to create a TCP socket that uses encryption.
    - Encrypted_TCP_Server: This class is used to create a TCP server that uses encryption.
    - Encrypted_TCP_Client: This class is used to create a TCP client that uses encryption. 
"""
import rsa
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA256
import socket
from threading import Thread
import time
import math
from logger import Logger
import uuid
#import Fernet
from cryptography.fernet import Fernet
from Crypto.Cipher import DES
logger = Logger(debugging_mode=True)

class Useful_Functions:
    def split_data(encrypted_msg, packet_size=4096):
        """This function splits the encrypted message into packets of 4096 bytes.
        It also adds a b'END' packet at the end.

        Args:
            encrypted_msg (bytes): The encrypted message.
        
        Returns:
            list: A list of packets.
        """
        packets = []

        for i in range(0, len(encrypted_msg)-packet_size, packet_size):
            packets.append(encrypted_msg[i:i+packet_size])

        data = encrypted_msg[len(encrypted_msg)- len(encrypted_msg)%packet_size:]
        if len(data) > 0:
            packets.append(data)

        return packets
    
    def get_MAC_address():
        """This function returns the MAC address of the computer

        Returns:
            str: The MAC address of the computer
        """
        mac = hex(uuid.getnode()).replace('0x', '').upper()
        return ':'.join([mac[i: i + 2] for i in range(0, 11, 2)])

class Cipher:
    """This class is used to encrypt and decrypt messages using AES-EAX mode.
    It also authenticates the messages using HMAC.
    """
    def __init__(self, key=None, bytes=32):
        """This function initializes the cipher.

        Args:
            key (bytes, optional): The key to use. If None, a random key is generated. Defaults to None.
            bytes (int, optional): The number of bytes to use for the key. Defaults to 32.
        """
        self.bytes = bytes
        if key == None:
            self.__key = get_random_bytes(bytes)
        else:
            self.__key = key
        
    def encrypt(self, msg):
        """This function encrypts the message

        Args:
            msg (bytes): The message to encrypt

        Returns:
            bytes: The encrypted message
        """
        cipher = AES.new(self.__key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(msg)
        return cipher.nonce + tag + ciphertext
    
    def decrypt(self, msg):
        """This function decrypts a full message(a message that includes the nonce, tag and ciphertext)

        Args:
            msg (bytes): The message to decrypt

        Returns:
            bytes: The decrypted message
        """
        nonce = msg[:16]
        tag = msg[16:32]
        ciphertext = msg[32:]
        return self.basic_decrypt(ciphertext, nonce, tag)
        
    def basic_decrypt(self, msg, nonce, tag):
        """This function decrypts a message that only includes the ciphertext.
        It also authenticates the message using the nonce and tag.

        Args:
            msg (bytes): The message to decrypt

        Returns:
            bytes: The decrypted message
        """
        cipher = AES.new(self.__key, AES.MODE_EAX, nonce=nonce)
        return cipher.decrypt_and_verify(msg, tag)
    
    def set_key(self, key):
        """This function sets the key of the cipher.

        Args:
            key (bytes): The key to use.
        """
        if len(key) == self.bytes:
            self.__key = key
    
    def get_key(self):
        """This function returns the key of the cipher.

        Returns:
            bytes: The key of the cipher
        """
        return self.__key

class Cipher_ECB:
    """This class is used to encrypt and decrypt messages using DES mode.
    It also authenticates the messages using HMAC.
    """
    def __init__(self, key=None, bytes=16):
        """This function initializes the cipher.

        Args:
            key (bytes, optional): The key to use. If None, a random key is generated. Defaults to None.
            bytes (int, optional): The number of bytes to use for the key. Defaults to 32.
        """
        self.bytes = bytes
        if key == None:
            self.__key = get_random_bytes(bytes)
        else:
            self.__key = key
        
        self.__cipher = AES.new(self.__key, AES.MODE_ECB)
        
    def encrypt(self, msg):
        """This function encrypts the message

        Args:
            msg (bytes): The message to encrypt

        Returns:
            bytes: The encrypted message
        """
        ciphertext = self.__cipher.encrypt(pad(msg, AES.block_size))
        return ciphertext
    
    def decrypt(self, msg):
        """This function decrypts a full message(a message that includes the nonce, tag and ciphertext)

        Args:
            msg (bytes): The message to decrypt

        Returns:
            bytes: The decrypted message
        """
        decrypted = self.__cipher.decrypt(msg[:len(msg)-AES.block_size])
        try:
            decrypted += unpad(self.__cipher.decrypt(msg[-AES.block_size:]), AES.block_size)
        except ValueError as e:
            print(e)
        return decrypted
    
    def set_key(self, key):
        """This function sets the key of the cipher.

        Args:
            key (bytes): The key to use.
        """
        if len(key) == self.bytes:
            self.__key = key
    
    def get_key(self):
        """This function returns the key of the cipher.

        Returns:
            bytes: The key of the cipher
        """
        return self.__key

class Encrypted_TCP_Socket:
    """This class is used to create a TCP socket that uses encryption.
    """
    def __init__(self, ip, port):
        """This function initializes the socket and connects to the server.

        Args:
            ip (string): The IP address of the server.
            port (int): The port of the server.
        """
        self.ip = ip
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.cipher = Cipher()
        
    def handle_connection(self):
        """This function handles the connection to the server.
        """
        raise NotImplementedError("This function must be implemented by a subclass")

    def initiate_encrypted_data_transfer(self):
        """This function initiates the encrypted data transfer.
        """
        raise NotImplementedError("This function must be implemented by a subclass")
    
    def send_data(self, msg, socket = None, packet_size=4096):
        """This function encrypts the message and sends it to the server.

        Args:
            msg (string): The message to send.
            socket (socket): The socket used to send the data.
        """
        if socket == None:
            socket = self.socket
        
        if type(msg) == str:
            msg = msg.encode()

        ciphertext = self.cipher.encrypt(msg)
        packets = Useful_Functions.split_data(ciphertext, packet_size=packet_size)
        first_packet = str(hex(len(packets))).encode().replace(b'0x', b'').zfill(4)
        first_packet += str(hex(packet_size)).encode().replace(b'0x', b'').zfill(4)
        first_packet = self.cipher.encrypt(first_packet)
        socket.send(first_packet)
        
        for packet in packets:
            socket.send(packet)

        response = socket.recv(39)
        response = self.cipher.decrypt(response)
        
        return response == b"SUCCESS"
    
    def decrypt_data(self, data):
        """This function decrypts the data using the AES-256 key.

        Args:
            data (bytes): The data to decrypt.

        Returns:
            bytes: The decrypted data, or False if the decryption failed
        """
        
        msg = self.cipher.decrypt(data)
        
        return msg

    def recv_data(self, socket = None):
        """This function receives data from the server.
        """
        if socket == None:
            socket = self.socket

        full_data = b''
        data = socket.recv(40)
        data = self.decrypt_data(data)
        num_packets = int(data[:4], 16)
        packet_size = int(data[4:8], 16)
        for i in range(num_packets):
            data = socket.recv(packet_size)
            full_data += data

        msg = b'SUCCESS'
        msg = self.cipher.encrypt(msg)
        socket.send(msg)
        
        return self.decrypt_data(full_data)

class Encrypted_UDP_Socket:
    def __init__(self, local_ip, local_port, dest_ip, dest_port, key):
        """This function initializes the socket and connects to the server.

        Args:
            dest_ip (string): The IP address of the server.
            dest_port (int): The port of the server.
            local_ip (string, optional): The IP address of the local machine. Defaults to None.
            local_port (int, optional): The port of the local machine. Defaults to None.
        """
        self.dest_ip = dest_ip
        self.dest_port = dest_port
        self.local_ip = local_ip
        self.local_port = local_port
        self.logger_name = "Root"

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((local_ip, local_port))

        self.cipher = Cipher_DES(key)
        
    def send_data(self, msg, packet_size=16384):
        """This function encrypts the message and sends it to the server.

        Args:
            msg (string): The message to send.
            socket (socket): The socket used to send the data.
        """
        print(len(msg))
        if type(msg) == str:
            msg = msg.encode()

        ciphertext = self.cipher.encrypt(msg)
        
        first_packet = str(hex(len(ciphertext))).encode().replace(b'0x', b'').zfill(8)
       
        logger.log_debug(f"Sending First Packet: {first_packet}")

        first_packet = self.cipher.encrypt(first_packet)

        self.socket.sendto(first_packet, (self.dest_ip, self.dest_port))
        
        self.socket.sendto(ciphertext, (self.dest_ip, self.dest_port))
        
        
        data, addr = self.socket.recvfrom(16)
        data = self.cipher.decrypt(data)
        logger.log_debug(f"Received response: {data}", self.logger_name)

    def recv_data(self):
        """This function receives data from the server.
        """
        
        full_data = b''
        data, addr = self.socket.recvfrom(16)
        data = self.cipher.decrypt(data)
        logger.log_debug(f"Received First Packet: {data}", self.logger_name)
        
        packet_size = int(data, 16)
        logger.log_debug(f"Packet Size: {packet_size}", self.logger_name)
        
        
        data, addr = self.socket.recvfrom(packet_size)
        logger.log_debug(f"Received packet: {len(data)}", self.logger_name)
        msg = b'SUCCESS'
        msg = self.cipher.encrypt(msg)
        self.socket.sendto(msg, addr)
        logger.log_debug(f"Sent response: {msg}", self.logger_name)

        return self.cipher.decrypt(data)

class Encrypted_TCP_Client(Encrypted_TCP_Socket):
    def __init__(self, ip='127.0.0.1', port=25565, DES_key=None):
        """This function initializes the socket and connects to the server.

        Args:
            ip (string): The IP address of the server.
            port (int): The port of the server.
        """
        self.logger_name = 'TCP Client'
        logger.create_logger(self.logger_name)
        super().__init__(ip, port)
        if DES_key:
            self.cipher = Cipher_DES(DES_key)
        self.socket.connect((ip, port))
        logger.log('Connected to server at ' + ip + ':' + str(port), log_type='info', logger_name=self.logger_name)

    def handle_connection(self):
        """This function handles the connection to the server.
        """
        self.initiate_encrypted_data_transfer()

    def initiate_encrypted_data_transfer(self):
        """This function initiates the encrypted data transfer.
        """
        logger.log('Initiating encrypted data transfer', log_type='info', logger_name=self.logger_name)
        self.socket.send(b"INITIATE_ENCRYPTED_DATA_TRANSFER")

        logger.log('Sent INITIATE_ENCRYPTED_DATA_TRANSFER', log_type='debug', logger_name=self.logger_name)

        server_public_key = self.socket.recv(4096)
        logger.log('Received server public key', log_type='debug', logger_name=self.logger_name)
        rsa_encryptor = rsa.PublicKey.load_pkcs1(server_public_key)

        msg = self.cipher.get_key()

        logger.log('Generated key', log_type='debug', logger_name=self.logger_name)
        logger.log(f'Key: {self.cipher.get_key()}', log_type='debug', logger_name=self.logger_name)

        msg = rsa.encrypt(msg, rsa_encryptor)
        self.socket.send(msg)
        logger.log('Sent encrypted key', log_type='debug', logger_name=self.logger_name)

        response = self.recv_data(self.socket)
        logger.log(f'Received: {response}', log_type='debug', logger_name=self.logger_name)

        if response == b'ENCRYPTED_DATA_TRANSFER_INITIATED':
            logger.log('Encrypted data transfer initiated', log_type='info', logger_name=self.logger_name)
        else:
            logger.log('Encrypted data transfer failed to initiate. trying again...', log_type='warning', logger_name=self.logger_name)
            self.initiate_encrypted_data_transfer()

    def send_MAC(self):
        """This function sends the MAC address of the client to the server.
        """
        self.send_data(Useful_Functions.get_MAC_address())
        logger.log('Sent MAC address', log_type='debug', logger_name=self.logger_name)

class Encrypted_TCP_Server(Encrypted_TCP_Socket):
    def __init__(self, ip = '0.0.0.0', port = 25565, DES_key = None, max_connections = 40):
        """This function initializes the socket and waits for a connection from a client.

        Args:
            ip (string): The IP address of the server.
            port (int): The port of the server.
        """
        global logger
        self.logger_name = 'TCP Server'
        logger.create_logger(self.logger_name)

        super().__init__(ip, port)
        if DES_key:
            self.cipher = Cipher_DES(DES_key)
        self.socket.bind((ip, port))
        logger.log('Server started at ' + ip + ':' + str(port), log_type='info', logger_name=self.logger_name)
        (self.public_key, self.private_key) = rsa.newkeys(1024)
    
    def send_data(self, msg, client_socket):
        return super().send_data(msg, socket = client_socket)

    def recv_data(self, client_socket):
        return super().recv_data(socket = client_socket)

    def wait_for_connections(self):
        """This function waits for a connection from a client.
        """
        self.socket.listen()
        self.conns = {}
        logger.log('Waiting for connections...', log_type='info', logger_name=self.logger_name)
        while True:
            client_soc, client_address = self.socket.accept()
            logger.log(f'Connection from {client_address[0]}:{client_address[1]}', log_type='info', logger_name=self.logger_name)
            self.conns[client_address] = None
            Thread(target=self.handle_connection, args=(client_soc, client_address)).start()
        
    def handle_connection(self, client_soc, client_address):
        """This function handles the connection to the server.
        """
        encrypted_communication = False
        while not encrypted_communication:
            encrypted_communication = self.initiate_encrypted_data_transfer(client_soc, client_address)
        
        logger.log(f'Encrypted data transfer initiated with {client_address[0]}:{client_address[1]}', log_type='info', logger_name=self.logger_name)
        self.conns[client_address] = self.get_MAC(client_soc, client_address)


    def initiate_encrypted_data_transfer(self, client_soc, client_address):
        """This function initiates the encrypted data transfer.
        """
        logger.log(f'Initiating encrypted data transfer with {client_address[0]}:{client_address[1]}', log_type='info', logger_name=self.logger_name)
        response = client_soc.recv(4096)
        logger.log(f'Received: {response}', log_type='debug', logger_name=self.logger_name)
        if response == b'INITIATE_ENCRYPTED_DATA_TRANSFER':
            client_soc.send(self.public_key.save_pkcs1())
            logger.log(f'Sent public key to {client_address[0]}:{client_address[1]}', log_type='debug', logger_name=self.logger_name)

            AES_key = client_soc.recv(4096)
            logger.log(f'Received encrypted key and iv from {client_address[0]}:{client_address[1]}', log_type='debug', logger_name=self.logger_name)
            AES_key = rsa.decrypt(AES_key, self.private_key)
            self.cipher = Cipher(AES_key)
            logger.log('created Cipher', log_type='debug', logger_name=self.logger_name)
            logger.log(f'Key: {self.cipher.get_key()}', log_type='debug', logger_name=self.logger_name)

            self.send_data(b"ENCRYPTED_DATA_TRANSFER_INITIATED", client_soc)
            logger.log(f'Sent ENCRYPTED_DATA_TRANSFER_INITIATED to {client_address[0]}:{client_address[1]}', log_type='debug', logger_name=self.logger_name)
            return True
        else:
            logger.log(f'Encrypted data transfer failed to initiate with {client_address[0]}:{client_address[1]}.\ntrying again...', log_type='warning', logger_name=self.logger_name)
            return self.initiate_encrypted_data_transfer(client_soc, client_address)
    
    def get_MAC(self, client_soc, client_address):
        """This function gets the MAC address of the client.

        Args:
            client_soc (socket): The socket of the client.

        Returns:
            string: The MAC address of the client.
        """
        self.send_data("GET_MAC", client_soc)
        MAC = self.recv_data(client_soc).decode()
        
        if len(MAC.split(':')) == 6:
            logger.log(f'Received MAC address from {client_address[0]}:{client_address[1]}', log_type='debug', logger_name=self.logger_name)
            logger.log(f'MAC: {MAC}', log_type='debug', logger_name=self.logger_name)
            return MAC
        
        else:
            logger.log(f'Failed to get MAC address from {client_address[0]}:{client_address[1]}', log_type='warning', logger_name=self.logger_name)
            return self.get_MAC(client_soc, client_address)

    
def main():
    cipher = DES.new(get_random_bytes(8), DES.MODE_ECB)
    msg = b'01234567891234567'
    msg = cipher.encrypt(pad(msg, DES.block_size))
    #msg = msg[:1] + b'a' + msg[2:]
    print(len(msg))
    start = time.time()
   

    decrypted_msg = unpad(cipher.decrypt(msg), AES.block_size)
    print(decrypted_msg)

    
    print(time.time() - start)


if __name__ == "__main__":
    main()