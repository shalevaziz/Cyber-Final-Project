from mss import mss
import time
from PIL import Image
from zlib import compress, decompress
import socket
from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import time
import cv2
from pyautogui import screenshot
import numpy as np
import pyautogui
from basics import Cipher_ECB, Encrypted_TCP_Socket, Useful_Functions
from threading import Thread, Lock
from logger import Logger

logger = Logger()
logger_name = 'ScreenShare'
logger.create_logger(logger_name)

MULTIPLE = 0.8
RESULUTIONS = (1536, 864)
QUALITY = 95

class Encrypted_TCP_Server_For_ScreenShare:
    def __init__(self, local_ip, local_port, key):
        """This function initializes the ScreenShare
        """
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind((local_ip, local_port))

        self.logger_name = 'Encrypted_TCP_Server_For_ScreenShare'
        logger.create_logger(self.logger_name, 'ScreenShare')
        self.cipher = Cipher_ECB(key)
        self.connected = False
        self.start()
    
    def start(self):
        """This function handles the connection
        """
        self.socket.listen(1)
        logger.log_debug('Listening for connections', self.logger_name)
        self.client_socket, self.address = self.socket.accept()
        print('Connected to: ' + str(self.address))
        self.connected = True

    def send_data(self, msg, packet_size=4096):
        """This function sends data to the client

        Args:
            data (bytes): The data to send.
        """
        if type(msg) == str:
            msg = msg.encode()

        ciphertext = self.cipher.encrypt(msg)
        packets = Useful_Functions.split_data(ciphertext, packet_size=packet_size)
        first_packet = str(hex(len(packets))).encode().replace(b'0x', b'').zfill(4)
        first_packet += str(hex(packet_size)).encode().replace(b'0x', b'').zfill(4)
        first_packet += str(hex(len(packets[-1]))).encode().replace(b'0x', b'').zfill(4)
        first_packet = self.cipher.encrypt(first_packet)
        print(first_packet, len(first_packet))

        self.client_socket.send(first_packet)
        
        for packet in packets:
            self.client_socket.send(packet)

    def recv_data(self, packet_size=4096):
        
        full_data = b''
        data = self.socket.recv(16)
        data = self.cipher.decrypt(data)
        num_packets = int(data[:4], 16)
        packet_size = int(data[4:8], 16)
        last_packet_size = int(data[8:12], 16)
        for i in range(num_packets-1):
            data = self.socket.recv(packet_size)
            full_data += data

        data = self.socket.recv(last_packet_size)
        full_data += data

        full_data = self.cipher.decrypt(full_data)
        return full_data
 
class ScreenShare_Transmitter:
    def __init__(self, local_ip, local_port, key, x_res=RESULUTIONS[0], y_res=RESULUTIONS[1]):
        """This function initializes the ScreenShare
        """
        self.socket = Encrypted_TCP_Server_For_ScreenShare(local_ip, local_port, key)
        self.stream = True
        self.logger_name = 'ScreenShare_Viewer'
        self.socket.logger_name = self.logger_name
        logger.create_logger(self.logger_name, 'ScreenShare')
        self.frames = []

    def start_stream(self):
        """This function starts the ScreenShare
        """
        i = 0
        while not self.socket.connected:
            pass
        
        while self.stream:
            self.img = self.take_screenshot()
            self.socket.send_data(self.img)
            i += 1
            logger.log_debug('Sent frame: ' + str(i), self.logger_name)
            
    def take_screenshot(self):
        """This function takes a screenshot of the screen.

        Returns:
            bytes: The screenshot of the screen.
        """
        frame = pyautogui.screenshot()
        frame = np.array(frame)
        frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
        frame = cv2.resize(frame, RESULUTIONS, interpolation=cv2.INTER_AREA)
        result, frame = cv2.imencode('.jpg', frame, [int(cv2.IMWRITE_JPEG_QUALITY), QUALITY])
        frame = frame.tobytes()
        return frame

class Encrypted_TCP_Client_For_ScreenShare:
    def __init__(self, ip, port, key):
        """This function initializes the ScreenShare
        """
        self.logger_name = 'Encrypted_TCP_Client_For_ScreenShare'
        logger.create_logger(self.logger_name, 'ScreenShare')

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        self.ip = ip
        self.port = port
        self.connected = False
        self.socket.connect((self.ip, self.port))
        print('Connected to ' + self.ip + ':' + str(self.port))
        self.connected = True
        self.cipher = Cipher_ECB(key)
        
    def send_data(self, msg, packet_size=4096):
        """This function sends data to the client

        Args:
            data (bytes): The data to send.
        """
        if type(msg) == str:
            msg = msg.encode()

        ciphertext = self.cipher.encrypt(msg)
        packets = Useful_Functions.split_data(ciphertext, packet_size=packet_size)
        first_packet = str(hex(len(packets))).encode().replace(b'0x', b'').zfill(4)
        first_packet += str(hex(packet_size)).encode().replace(b'0x', b'').zfill(4)
        first_packet += str(hex(len(packets[-1]))).encode().replace(b'0x', b'').zfill(4)
        first_packet = self.cipher.encrypt(first_packet)
        self.socket.send(first_packet)
        
        for packet in packets:
            self.socket.send(packet)

    def recv_data(self):
        
        full_data = b''
        data = self.socket.recv(16)
        data = self.cipher.decrypt(data)
        num_packets = int(data[:4], 16)
        packet_size = int(data[4:8], 16)
        last_packet_size = int(data[8:12], 16)

        for i in range(num_packets-1):
            data = self.socket.recv(packet_size)
            full_data += data

        data = self.socket.recv(last_packet_size)
        full_data += data

        full_data = self.cipher.decrypt(full_data)
        return full_data

class ScreenShare_Viewer:
    def __init__(self, local_ip, local_port, key, fullscreen = False, x_res=RESULUTIONS[0], y_res=RESULUTIONS[1]):
        """This function initializes the ScreenShare
        """
        self.socket = Encrypted_TCP_Client_For_ScreenShare(local_ip, local_port, key)
        self.stream = True
        self.logger_name = 'ScreenShare_Transmitter'
        self.socket.logger_name = self.logger_name
        self.img = None
        self.frame_num = 0
        logger.create_logger(self.logger_name, 'ScreenShare')
    
    def recv_frame(self):
        """This function starts the ScreenShare
        """
        i = 0
        err_count = 0

        try:
            img = self.socket.recv_data()
        except Exception as e:
            img = None
            err_count += 1
            print(e)
            print('Error count: ' + str(err_count))


        if img is not None:
            self.img = cv2.imdecode(np.frombuffer(img, np.uint8), cv2.IMREAD_COLOR)
            self.frame_num += 1
        
        
        logger.log_debug('Received frame: ' + str(i), self.logger_name)

    def show_stream(self):
        """This function starts the ScreenShare
        """
        state = 1
        while not self.socket.connected:
            pass
        
        while self.img is None:
            pass
        start = time.time()
        while self.stream and state >= 0:
            try:
                state = cv2.getWindowProperty('frame', 0)
            except cv2.error:
                state -= 1

            
            cv2.imshow('frame', self.img)
            cv2.waitKey(1)
        
        print('Stream ended')
        print('Frame amount: ' + str(self.frame_num))
        print('Time: ' + str(time.time() - start))
        print('FPS: ' + str(self.frame_num / (time.time() - start)))
        self.stream = False

    def start_stream(self):
        """This function starts the ScreenShare
        """
        state = 1
        while not self.socket.connected:
            pass
        
        Thread(target=self.show_stream).start()

        while self.stream:
            self.recv_frame()
            
        self.stream = False

def main():
    """start = time.time()
    cipher = Cipher_DES()
    total_bytes = 0
    state = 1
    while state >= 0:
        frame = pyautogui.screenshot()
        frame = np.array(frame)
        frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
        frame = cv2.resize(frame, (1536, 864), interpolation=cv2.INTER_AREA)
        result, frame = cv2.imencode('.jpg', frame, [int(cv2.IMWRITE_JPEG_QUALITY), 95])
        frame = frame.tobytes()
        total_bytes += len(frame)
        self.img = cv2.imdecode(np.frombuffer(frame, np.uint8), cv2.IMREAD_COLOR)
        try:
            state = cv2.getWindowProperty('frame', 0)
        except cv2.error:
            state -= 1
        cv2.imshow('frame', self.img)
        print(state)
        cv2.waitKey(1)
            
            #save image to file

    print(time.time() - start)
    print(total_bytes/1024/1024)"""
    
    viewer = ScreenShare_Transmitter('0.0.0.0', 25565, b'12345678')
    viewer.start_stream()
    
if __name__ == '__main__':
    main()
