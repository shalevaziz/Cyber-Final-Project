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
import os
logger = Logger(debugging_mode=True)

class Useful_Functions:
    @staticmethod
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
    
    @staticmethod
    def get_MAC_address():
        """This function returns the MAC address of the computer

        Returns:
            str: The MAC address of the computer
        """
        mac = hex(uuid.getnode()).replace('0x', '').upper()
        return ':'.join([mac[i: i + 2] for i in range(0, 11, 2)])

    @staticmethod
    def read_file(file_path: str, chunk_size=4096):
        """This function reads a file and returns its contents

        Args:
            file_path (str): The path to the file

        Returns:
            bytes: The contents of the file
        """
        with open(file_path, 'rb') as f:
            while True:
                data = f.read(chunk_size)
                if not data:
                    break
                yield data
        yield b'EOF'
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
        ciphertext = self.__cipher.encrypt(msg)
        return ciphertext
    
    def decrypt(self, msg):
        """This function decrypts a full message(a message that includes the nonce, tag and ciphertext)

        Args:
            msg (bytes): The message to decrypt

        Returns:
            bytes: The decrypted message
        """
        decrypted = self.__cipher.decrypt(msg)
        
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
    
    def __send_packet(self, packet, socket = None):
        self.socket.send(self.cipher.encrypt(packet))
        response = self.socket.recv(17)
        
        try:
            response = self.cipher.decrypt(response)
        except ValueError:
            response = b'0'
        
        while response != b'1':
            self.socket.send(packet)
            response = self.socket.recv(17)
            try:
                response = self.cipher.decrypt(response)
            except ValueError:
                response = b'0'
    
    def recv_packet(self, socket = None):
        
        if socket == None:
            socket = self.socket
        
        length = socket.recv(48)
        recieved = False
        try:
            length = self.cipher.decrypt(length)
            length = int.from_bytes(length, byteorder='big')
            recieved = True
        except ValueError:
            pass
        
        while not recieved:
            socket.send(b'0')
            length = socket.recv(48)
            try:
                length = self.cipher.decrypt(length)
                length = int.from_bytes(length, byteorder='big')
                recieved = True
            except ValueError:
                pass
        
        socket.send(b'1')
        
        recieved = False
        packet = socket.recv(length)
        
        try:
            packet = self.cipher.decrypt(packet)
            recieved = True
        except ValueError:
            pass
        
        while not recieved:
            socket.send(b'0')
            packet = socket.recv(length)
            try:
                packet = self.cipher.decrypt(packet)
                recieved = True
            except ValueError:
                pass
        
        socket.send(b'1')
        return packet

    def send_packet(self, packet, socket = None):
        
        packet_size = (len(packet)+32).to_bytes(16, byteorder='big')
        
        self.__send_packet(packet_size, socket)
        
        self.__send_packet(packet, socket)
        
    
    def send_data(self, msg, socket = None, packet_size=4096, is_file = False):
        """This function encrypts the message and sends it to the server.

        Args:
            msg (string): The message to send.
            socket (socket): The socket used to send the data.
        """
        if socket == None:
            socket = self.socket
        
        if type(msg) == str:
            msg = msg.encode()

        packets = Useful_Functions.split_data(msg, packet_size=(packet_size-32))
        
        first_packet = len(packets).to_bytes(16, byteorder='big')
        
        self.send_packet(first_packet, socket)
        
        for packet in packets:
            self.send_packet(packet, socket)

        socket.settimeout(10000)

        
        return True
    
    def recv_data(self, socket = None):
        """This function receives data from the server.
        """
        if socket == None:
            socket = self.socket

        full_data = b''
        packet_amount = self.recv_packet(socket)
        
        for i in range(int.from_bytes(packet_amount, byteorder='big')):
            packet = self.recv_packet(socket)
            full_data += packet
        
        return full_data
    
    def send_file(self, path):
        """This function sends a file to the server.

        Args:
            path (string): The path of the file to send.
        """
        file_gen = Useful_Functions.read_file(path, 4064)
        filename = path.split('/')[-1]
        
        self.send_data(filename)
        try:
            for buffer in file_gen:
                
                buffer = self.cipher.encrypt(buffer)
                self.socket.send(buffer)
        except StopIteration:
            print('sent eof')
        
    def recv_file(self, path):
        filename = self.recv_data().decode()
        path = os.path.join(path, filename)
        print(path)
        with open(path, 'wb') as file:
            while True:
                data = self.socket.recv(4096)
                data = self.decrypt_data(data)
                if data == b'EOF':
                    break
                file.write(data)
                print(data)

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

    def handle_connection(self):
        """This function handles the connection to the server.
        """
        self.socket.settimeout(5)
        self.connected = False
        while not self.connected:
            try:
                self.socket.connect((self.ip, self.port))
                self.connected = True
                print('Connected to server at ' + self.ip + ':' + str(self.port))
                break
            except socket.timeout:
                print('Connection timed out\nTrying again...')
                self.socket.close()
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            except ConnectionRefusedError:
                print('Connection refused\nTrying again...')
            except OSError:
                print('Host unreachable\nTrying again...')
            
            time.sleep(10)
                
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
    def __init__(self, ip = '0.0.0.0', port = 25565, max_connections = 40):
        """This function initializes the socket and waits for a connection from a client.

        Args:
            ip (string): The IP address of the server.
            port (int): The port of the server.
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
        """This function waits for a connection from a client.
        """
        self.socket.listen()
        print('Waiting for connections...')
        while True:
            client_soc, client_address = self.socket.accept()
            print(f'Connection from {client_address[0]}:{client_address[1]}')
            Thread(target=self.handle_connection, args=(client_soc, client_address)).start()

def main():
    pass


if __name__ == "__main__":
    main()