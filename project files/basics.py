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
import threading
import time
import math
from logger import Logger
import uuid
#import Fernet
from Crypto.Cipher import DES
import os

logger: Logger
logger = Logger(debugging_mode=True)

class Useful_Functions:
    """This class contains multiple useful functions. 
    """
    @staticmethod
    def split_data(encrypted_msg: bytes, packet_size: int=4096):
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
    def read_file(file_path: str, chunk_size: int = 4096):
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

    @staticmethod
    def correct_URL_format(url: str) -> str:
        """This function corrects the URL format.
        The output format is: http://www.example.com

        Args:
            url (str): The URL to correct

        Returns:
            str: The corrected URL
        """
        url = url.strip().lower()
        if not url.startswith('http://') and not url.startswith('https://'):
            url = 'http://' + url
        
        if 'www.' not in url:
            if 'http://' in url:
                url = url.replace('http://', 'http://www.')
            elif 'https://' in url:
                url = url.replace('https://', 'https://www.')
        
        return url
        
class Cipher:
    """This class is used to encrypt and decrypt messages using AES-EAX mode.
    It also authenticates the messages using HMAC.
    """


    def __init__(self, key: bytes = None, bytes: int = 32):
        """This function initializes the cipher.

        Args:
            key (bytes, optional): The key to use. If None, a random key is generated. Defaults to None.
            bytes (int, optional): The number of bytes to use for the key. Defaults to 32.
        """
        if key == None:
            self.__key = get_random_bytes(bytes)
        else:
            self.__key = key
        
    def encrypt(self, msg: bytes) -> bytes:
        """This function encrypts the message

        Args:
            msg (bytes): The message to encrypt

        Returns:
            bytes: The encrypted message
        """
        cipher = AES.new(self.__key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(msg)
        return cipher.nonce + tag + ciphertext
    
    def decrypt(self, msg: bytes) -> bytes:
        """This function decrypts a full message(a message that includes the nonce, tag and ciphertext)

        Args:
            msg (bytes): The message to decrypt

        Returns:
            bytes: The decrypted message
        """
        nonce = msg[:16]
        tag = msg[16:32]
        ciphertext = msg[32:]
        return self.__decrypt(ciphertext, nonce, tag)
        
    def __decrypt(self, msg: bytes, nonce: bytes, tag: bytes) -> bytes:
        """This function decrypts a message that only includes the ciphertext.
        It also authenticates the message using the nonce and tag.

        Args:
            msg (bytes): The message to decrypt

        Returns:
            bytes: The decrypted message
        """
        cipher = AES.new(self.__key, AES.MODE_EAX, nonce=nonce)
        return cipher.decrypt_and_verify(msg, tag)
    
    def set_key(self, key: bytes) -> None:
        """This function sets the key of the cipher.

        Args:
            key (bytes): The key to use.
        """
        if len(key) == self.bytes:
            self.__key = key
    
    def get_key(self) -> bytes:
        """This function returns the key of the cipher.

        Returns:
            bytes: The key of the cipher
        """
        return self.__key

class Cipher_ECB:
    """This class is used to encrypt and decrypt messages using ECB mode.
    """
    def __init__(self, key: bytes = None, bytes: int = 16):
        """This function initializes the cipher.

        Args:
            key (bytes, optional): The key to use. If None, a random key is generated. Defaults to None.
            bytes (int, optional): The number of bytes to use for the key. Defaults to 32.
        """
        if key == None:
            self.__key = get_random_bytes(bytes)
        else:
            self.__key = key
        
        self.__cipher = AES.new(self.__key, AES.MODE_ECB)
        
    def encrypt(self, msg: bytes) -> bytes:
        """This function encrypts the message

        Args:
            msg (bytes): The message to encrypt

        Returns:
            bytes: The encrypted message
        """
        ciphertext: bytes = self.__cipher.encrypt(msg)
        return ciphertext
    
    def decrypt(self, msg: bytes) -> bytes:
        """This function decrypts a full message(a message that includes the nonce, tag and ciphertext)

        Args:
            msg (bytes): The message to decrypt

        Returns:
            bytes: The decrypted message
        """
        decrypted: bytes = self.__cipher.decrypt(msg)
        
        return decrypted
    
    def set_key(self, key: bytes) -> None:
        """This function sets the key of the cipher.

        Args:
            key (bytes): The key to use.
        """
        if len(key) == self.bytes:
            self.__key = key
    
    def get_key(self) -> bytes:
        """This function returns the key of the cipher.

        Returns:
            bytes: The key of the cipher
        """
        return self.__key

class Encrypted_TCP_Socket:
    """This class is used as an abstract class for the client and server classes.
    """
    def __init__(self, ip: str, port: int):
        """This function initializes the socket and connects to the server.

        Args:
            ip (string): The IP address of the server.
            port (int): The port of the server.
        """
        self.ip = ip
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.cipher = Cipher()
        self.communication_lock = threading.Lock()
        
    def handle_connection(self):
        """This function handles the connection to the server.
        """
        raise NotImplementedError("This function must be implemented by a subclass")

    def initiate_encrypted_data_transfer(self):
        """This function initiates the encrypted data transfer.
        """
        raise NotImplementedError("This function must be implemented by a subclass")
    
    def __safe_send_packet(self, packet: bytes, socket: socket.socket = None) -> bool:
        """This function sends a packet to the connected peer. It ensures that the packet is sent successfully.
        

        Args:
            packet (bytes): The packet to send. the packet should be already encrypted.
            socket (socket): The socket used to send the packet.

        Returns:
            bool: True if the packet was sent successfully, False otherwise.
        """
        if socket == None:
            socket = self.socket
        
        socket.sendall(packet)
        response = socket.recv(33)
        response = self.cipher.decrypt(response)
        
        for i in range(10):
            try:
                if response == b'1':
                    return True
                socket.sendall(packet)
                response = socket.recv(33)
                response = self.cipher.decrypt(response)
            except:
                return False
    
    def __safe_recv_packet(self, socket: socket.socket = None, packet_size: int = 4096) -> bytes:
        """This function receives a packet from the connected peer. It ensures that the packet is received successfully.
        

        Args:
            socket (socket): The socket used to receive the packet.
            packet_size (int): The size of the packet to receive.

        Returns:
            bytes: The received packet.
        """
        if socket == None:
            socket = self.socket
        for i in range(10):
            packet = socket.recv(packet_size)
            try:
                packet = self.cipher.decrypt(packet)
                msg = b'1'
                msg = self.cipher.encrypt(msg)
                socket.sendall(msg)
                break
            except:
                msg = b'0'
                msg = self.cipher.encrypt(msg)
                socket.sendall(msg)
                packet = b''
                
        return packet
    
    def send_data(self, msg, socket:socket.socket = None, packet_size:int =4096, is_file:bool = False) -> bool:
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
        first_packet = len(packets).to_bytes(16, byteorder='big')
        first_packet += packet_size.to_bytes(16, byteorder='big')
        first_packet += len(packets[-1]).to_bytes(16, byteorder='big')
        first_packet = self.cipher.encrypt(first_packet)
        
        #! Acquired lock
        self.communication_lock.acquire()
        
        socket.send(first_packet)
        
        for packet in packets:
            socket.send(packet)

        response = socket.recv(39)
        response = self.cipher.decrypt(response)
        
        #! Released lock
        self.communication_lock.release()
        
        return response == b"SUCCESS"

    def recv_data(self, socket:socket.socket = None):
        """This function receives data from the server.
        """
        if socket == None:
            socket = self.socket

        full_data = b''
        
        #! Acquired lock
        self.communication_lock.acquire()
        
        data = socket.recv(80)
        data = self.cipher.decrypt(data)
        num_packets = int.from_bytes(data[:16], byteorder='big')
        packet_size = int.from_bytes(data[16:32], byteorder='big')
        last_packet = int.from_bytes(data[32:], byteorder='big')
        for i in range(num_packets-1):
            data = socket.recv(packet_size)
            full_data += data

        data = socket.recv(last_packet)
        full_data += data
        
        try:
            full_data = self.cipher.decrypt(full_data)
            msg = b'SUCCESS'
            
        except ValueError:
            msg = b'FAIL'
            full_data = b''
            
        msg = self.cipher.encrypt(msg)
        socket.send(msg)
        
        #! Released lock
        self.communication_lock.release()
        
        return full_data
    
    def send_file(self, path):
        """This function sends a file to the server.

        Args:
            path (string): The path of the file to send.
        """
        file_gen = Useful_Functions.read_file(path, 4064)
        filename = path.split('/')[-1]
        
        file_size = os.path.getsize(path)
        num_packets = math.ceil(file_size / 4064)
        last = file_size % 4064 + 32
        
        print(num_packets, last, filename)
        
        num_packets = num_packets.to_bytes(32, 'big')
        last = last.to_bytes(12, 'big')
        filename = filename.encode()
        
        msg = num_packets + last + filename
        
        self.send_data(msg)
        
        #! Acuired lock
        self.communication_lock.acquire()
        
        try:
            for buffer in file_gen:
                buffer = self.cipher.encrypt(buffer)
                self.__safe_send_packet(buffer)
        except StopIteration:
            print('sent eof')
        
        #! Released lock
        self.communication_lock.release()
        
    def recv_file(self, path):
        """This function receives a file from the server.

        Args:
            path (string): The path to save the file to.
        """
        
        
        msg = self.recv_data()
        
        num_packets = int.from_bytes(msg[:32], 'big')
        last = int.from_bytes(msg[32:44], 'big')
        filename = msg[44:].decode()
        
        print(num_packets, last, filename)
        
        path = os.path.join(path, filename)
        
        
        
        with open(path, 'wb') as file:
            print('opened file')
            
            #! Acquired lock
            self.communication_lock.acquire()
            
            for i in range(num_packets-1):
                time.sleep(0.01)
                data = self.__safe_recv_packet()
                file.write(data)
            data = self.__safe_recv_packet(packet_size=last)
            
            #! Released lock
            self.communication_lock.release()
            
            file.write(data)

        return path
class Encrypted_TCP_Client(Encrypted_TCP_Socket):
    """This class is used to create a client that uses AES EAX encrypted TCP connection
    to communicate with the server.
    """
    def __init__(self, ip='127.0.0.1', port=25565):
        """This function initializes the socket and connects to the server.

        Args:
            ip (string): The IP address of the server.
            port (int): The port of the server.
        """
        self.logger_name = 'TCP Client'
        logger.create_logger(self.logger_name)
        super().__init__(ip, port)

    def handle_connection(self):
        """This function handles the connection to the server.
        """
        self.socket.settimeout(1000)
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

    def initiate_encrypted_data_transfer(self) -> None:
        """This function initiates the encrypted data transfer with the server.
        """
        logger.log('Initiating encrypted data transfer', log_type='info', logger_name=self.logger_name)
        self.socket.send(b"INITIATE_ENCRYPTED_DATA_TRANSFER")

        server_public_key = self.socket.recv(4096)
        rsa_encryptor = rsa.PublicKey.load_pkcs1(server_public_key)

        msg = self.cipher.get_key()#Symmetric AES key

        msg = rsa.encrypt(msg, rsa_encryptor)
        self.socket.send(msg)#send encrypted key
        
        response = self.recv_data(self.socket)
        
        if response == b'ENCRYPTED_DATA_TRANSFER_INITIATED':
            logger.log('Encrypted data transfer initiated', log_type='info', logger_name=self.logger_name)
        else:
            #if initation failed, try again
            logger.log('Encrypted data transfer failed to initiate. trying again...', log_type='warning', logger_name=self.logger_name)
            self.initiate_encrypted_data_transfer()

    def send_MAC(self):
        """This function sends the MAC address of the client to the server.
        """
        self.send_data(Useful_Functions.get_MAC_address())
        logger.log('Sent MAC address', log_type='debug', logger_name=self.logger_name)

class Encrypted_TCP_Server(Encrypted_TCP_Socket):
    """This class is used to create a server that communicates using AES EAX encrypted TCP connection
    """
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
        for each connection, a new thread is created to handle it.
        """
        self.socket.listen()
        print('Waiting for connections...')
        while True:
            client_soc, client_address = self.socket.accept()
            print(f'Connection from {client_address[0]}:{client_address[1]}')
            Thread(target=self.handle_connection, args=(client_soc, client_address)).start()

def main():
    cipher = Cipher()
    print(len("".encode()))
    
if __name__ == "__main__":
    main()