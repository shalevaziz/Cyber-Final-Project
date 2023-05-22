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
from Crypto.Cipher import DES
logger = Logger(debugging_mode=True)

class Useful_Functions:
    """
    This class contains useful functions for working with data, such as splitting data into packets and getting the MAC address of the computer.
    """
    def split_data(encrypted_msg, packet_size=4096):
        """
        Splits the encrypted message into packets of a specified size and adds a b'END' packet at the end.

        Args:
            encrypted_msg (bytes): The encrypted message.
            packet_size (int): The size of each packet.

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
        """
        Returns the MAC address of the computer.

        Returns:
            str: The MAC address of the computer.
        """
        mac = hex(uuid.getnode()).replace('0x', '').upper()
        return ':'.join([mac[i: i + 2] for i in range(0, 11, 2)])
class Cipher:
    """
    This class is used to encrypt and decrypt messages using AES-EAX mode.
    It also authenticates the messages using HMAC.
    """
    def __init__(self, key=None, bytes=32):
        """
        Initializes the cipher.

        Args:
            key (bytes, optional): The key to use. If None, a random key is generated. Defaults to None.
            bytes (int, optional): The number of bytes to use for the key. Defaults to 32.
        """
        self.bytes = bytes
        if key is None:
            self.__key = get_random_bytes(bytes)
        else:
            self.__key = key
        
    def encrypt(self, msg):
        """
        Encrypts the message.

        Args:
            msg (bytes): The message to encrypt.

        Returns:
            bytes: The encrypted message.
        """
        cipher = AES.new(self.__key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(msg)
        return cipher.nonce + tag + ciphertext
    
    def decrypt(self, msg):
        """
        Decrypts a full message (a message that includes the nonce, tag and ciphertext).

        Args:
            msg (bytes): The message to decrypt.

        Returns:
            bytes: The decrypted message.
        """
        nonce = msg[:16]
        tag = msg[16:32]
        ciphertext = msg[32:]
        return self.basic_decrypt(ciphertext, nonce, tag)
        
    def basic_decrypt(self, msg, nonce, tag):
        """
        Decrypts a message that only includes the ciphertext.
        It also authenticates the message using the nonce and tag.

        Args:
            msg (bytes): The message to decrypt.

        Returns:
            bytes: The decrypted message.
        """
        cipher = AES.new(self.__key, AES.MODE_EAX, nonce=nonce)
        return cipher.decrypt_and_verify(msg, tag)
    
    def set_key(self, key):
        """
        Sets the key of the cipher.

        Args:
            key (bytes): The key to use.
        """
        if len(key) == self.bytes:
            self.__key = key
    
    def get_key(self):
        """
        Returns the key of the cipher.

        Returns:
            bytes: The key of the cipher.
        """
        return self.__key
class Cipher_ECB:
    """
    This class is used to encrypt and decrypt messages using DES mode.
    It also authenticates the messages using HMAC.
    """
    def __init__(self, key=None, bytes=16):
        """
        Initializes the cipher.

        Args:
            key (bytes, optional): The key to use. If None, a random key is generated. Defaults to None.
            bytes (int, optional): The number of bytes to use for the key. Defaults to 16.
        """
        self.bytes = bytes
        if key is None:
            self.__key = get_random_bytes(bytes)
        else:
            self.__key = key
        
        self.__cipher = AES.new(self.__key, AES.MODE_ECB)
        
    def encrypt(self, msg):
        """
        Encrypts the message.

        Args:
            msg (bytes): The message to encrypt.

        Returns:
            bytes: The encrypted message.
        """
        ciphertext = self.__cipher.encrypt(msg)
        return ciphertext
    
    def decrypt(self, msg):
        """
        Decrypts a full message (a message that includes the nonce, tag and ciphertext).

        Args:
            msg (bytes): The message to decrypt.

        Returns:
            bytes: The decrypted message.
        """
        decrypted = self.__cipher.decrypt(msg)
        return decrypted
    
    def set_key(self, key):
        """
        Sets the key of the cipher.

        Args:
            key (bytes): The key to use.
        """
        if len(key) == self.bytes:
            self.__key = key
    
    def get_key(self):
        """
        Returns the key of the cipher.

        Returns:
            bytes: The key of the cipher.
        """
        return self.__key


class Encrypted_TCP_Socket:
    """
    This class is used to create a TCP socket that uses encryption.
    """
    def __init__(self, ip, port):
        """
        Initializes the socket and connects to the server.

        Args:
            ip (str): The IP address of the server.
            port (int): The port of the server.
        """
        self.ip = ip
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.cipher = Cipher()
        
    def handle_connection(self):
        """
        Handles the connection to the server.
        """
        raise NotImplementedError("This function must be implemented by a subclass")

    def initiate_encrypted_data_transfer(self):
        """
        Initiates the encrypted data transfer.
        """
        raise NotImplementedError("This function must be implemented by a subclass")
    
    def send_data(self, msg, socket=None, packet_size=4096):
        """
        Encrypts the message and sends it to the server.

        Args:
            msg (bytes): The message to send.
            socket (socket, optional): The socket used to send the data. Defaults to None.

        Returns:
            bool: True if the message was sent successfully, False otherwise.
        """
        if socket is None:
            socket = self.socket
        
        if isinstance(msg, str):
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
        """
        Decrypts the data using the AES-256 key.

        Args:
            data (bytes): The data to decrypt.

        Returns:
            bytes: The decrypted data, or False if the decryption failed.
        """
        msg = self.cipher.decrypt(data)
        return msg if msg else False

    def recv_data(self, socket=None):
        """
        Receives data from the server.

        Args:
            socket (socket, optional): The socket used to receive the data. Defaults to None.

        Returns:
            bytes: The decrypted data, or False if the decryption failed.
        """
        if socket is None:
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
    """
    This class represents an encrypted UDP socket that can send and receive data from a server.
    """
    def __init__(self, local_ip, local_port, dest_ip, dest_port, key):
        """
        Initializes the socket and connects to the server.

        Args:
            local_ip (str): The IP address of the local machine.
            local_port (int): The port of the local machine.
            dest_ip (str): The IP address of the server.
            dest_port (int): The port of the server.
            key (bytes): The key used for encryption.
        """
        self.dest_ip = dest_ip
        self.dest_port = dest_port
        self.local_ip = local_ip
        self.local_port = local_port

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((local_ip, local_port))

        self.cipher = Cipher_DES(key)
        
    def send_data(self, msg, packet_size=16384):
        """
        Encrypts the message and sends it to the server.

        Args:
            msg (str): The message to send.
            packet_size (int): The size of each packet.
        """
        if type(msg) == str:
            msg = msg.encode()

        ciphertext = self.cipher.encrypt(msg)
        
        first_packet = str(hex(len(ciphertext))).encode().replace(b'0x', b'').zfill(8)

        first_packet = self.cipher.encrypt(first_packet)

        self.socket.sendto(first_packet, (self.dest_ip, self.dest_port))
        
        self.socket.sendto(ciphertext, (self.dest_ip, self.dest_port))
        
        
        data, addr = self.socket.recvfrom(16)
        data = self.cipher.decrypt(data)

    def recv_data(self):
        """
        Receives data from the server.

        Returns:
            bytes: The decrypted data received from the server.
        """
        full_data = b''
        data, addr = self.socket.recvfrom(16)
        data = self.cipher.decrypt(data)
        
        packet_size = int(data, 16)
        
        data, addr = self.socket.recvfrom(packet_size)
        
        msg = b'SUCCESS'
        msg = self.cipher.encrypt(msg)
        self.socket.sendto(msg, addr)

        return self.cipher.decrypt(data)

class Encrypted_TCP_Client(Encrypted_TCP_Socket):
    """
    This class represents an encrypted TCP client that can connect to a server and send and receive data.
    """
    def __init__(self, ip='127.0.0.1', port=25565, DES_key=None):
        """
        Initializes the socket and connects to the server.

        Args:
            ip (str): The IP address of the server.
            port (int): The port of the server.
            DES_key (bytes, optional): The key used for encryption. Defaults to None.
        """
        self.logger_name = 'TCP Client'
        logger.create_logger(self.logger_name)
        super().__init__(ip, port)
        if DES_key:
            self.cipher = Cipher_DES(DES_key)

        

    def handle_connection(self):
        """
        Handles the connection to the server.
        """
        self.socket.settimeout(5)
        self.connected = False
        while not self.connected:
            try:
                self.socket.connect((self.ip, self.port))
                self.connected = True
                print('Connected to server at ' + self.ip + ':' + str(self.port))
            except socket.timeout:
                print('Connection timed out\nTrying again...')
                self.socket.close()
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            except ConnectionRefusedError:
                print('Connection refused\nTrying again...')
            except OSError:
                print('Host unreachable\nTrying again...')
            
            time.sleep(10)
        self.socket.settimeout(1000000)
        self.initiate_encrypted_data_transfer()

    def initiate_encrypted_data_transfer(self):
        """
        Initiates the encrypted data transfer.
        """
        logger.log('Initiating encrypted data transfer', log_type='info', logger_name=self.logger_name)
        self.socket.send(b"INITIATE_ENCRYPTED_DATA_TRANSFER")

        server_public_key = self.socket.recv(4096)

        rsa_encryptor = rsa.PublicKey.load_pkcs1(server_public_key)

        msg = self.cipher.get_key()

        msg = rsa.encrypt(msg, rsa_encryptor)
        self.socket.send(msg)

        response = self.recv_data(self.socket)

        if response == b'ENCRYPTED_DATA_TRANSFER_INITIATED':
            logger.log('Encrypted data transfer initiated', log_type='info', logger_name=self.logger_name)
            print('success')
        else:
            logger.log('Encrypted data transfer failed to initiate. trying again...', log_type='warning', logger_name=self.logger_name)
            print('trying again')
            self.initiate_encrypted_data_transfer()

    def send_MAC(self):
        """
        Sends the MAC address of the client to the server.
        """
        self.send_data(Useful_Functions.get_MAC_address())
        logger.log('Sent MAC address', log_type='debug', logger_name=self.logger_name)

class Encrypted_TCP_Server(Encrypted_TCP_Socket):
    """
    This class represents an encrypted TCP server that can accept connections from clients and send and receive data.
    """
    def __init__(self, ip='0.0.0.0', port=25565, max_connections=40):
        """
        Initializes the socket and waits for a connection from a client.

        Args:
            ip (str): The IP address of the server.
            port (int): The port of the server.
            max_connections (int): The maximum number of connections allowed.
        """
        global logger
        self.logger_name = 'TCP Server'
        logger.create_logger(self.logger_name)
        self.conns = {}

        super().__init__(ip, port)
        self.socket.bind((ip, port))
        logger.log('Server started at ' + ip + ':' + str(port), log_type='info', logger_name=self.logger_name)
        ip = socket.gethostbyname(socket.gethostname())
        print('Server started at ' + ip + ':' + str(port))
    
    def wait_for_connections(self):
        """
        Waits for a connection from a client.
        """
        self.socket.listen()
        print('Waiting for connections...')
        while True:
            client_soc, client_address = self.socket.accept()
            print(f'Connection from {client_address[0]}:{client_address[1]}')
            self.conns[client_address] = None
            Thread(target=self.handle_connection, args=(client_soc, client_address)).start()
    
    
def main():
    pass


if __name__ == "__main__":
    main()