import cv2
import numpy as np
import socket
import pyautogui
import threading
from basics import Cipher_ECB
import time

RESOLUTIONS: tuple[int, int] = (1536, 864)
PACKET_SIZE: int = 65504
HEADER_SIZE: int = 7


class Sender:
    """A class that shares this PC's screen to a remote destination.

    Attributes:
        local_ip (str): The local IP address to bind the socket to.
        local_port (int): The local port to bind the socket to.
        dest_ip (str): The IP address of the remote destination.
        dest_port (int): The port of the remote destination.
        key (bytes): The encryption key to use for encrypting the data.
    """
    def __init__(self, local_ip: str, local_port: int, dest_ip: str, dest_port: int, key: bytes):
        self.local_ip = local_ip
        self.local_port = local_port
        self.dest_ip = dest_ip
        self.dest_port = dest_port
        
        self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.s.bind((self.local_ip, self.local_port))
        self.stream = True

        self.key = key
        self.cipher = Cipher_ECB(self.key)

    def listen_for_stop(self):
        """A function that listens for a stop signal from the remote destination.

        If a stop signal is received, the stream is stopped.
        """
        while True:
            data, addr = self.s.recvfrom(16)
            data = self.cipher.decrypt(data)
            if data == b'STOP000000000000':
                self.stream = False
                break
    
    def start_stream(self):
        """A function that starts the stream of screenshots.

        This function takes screenshots of the screen, splits them into packets, and sends them to the remote destination.
        """
        threading.Thread(target=self.listen_for_stop).start()
        while self.stream:
            frame = self.take_screenshot()
            packets = self.split_into_packets(frame)
            self.send_data(packets)

    def take_screenshot(self):
        """A function that takes a screenshot of the screen.

        Returns:
            bytes: The screenshot of the screen.
        """
        frame = np.array(pyautogui.screenshot())
        frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
        frame = cv2.resize(frame, RESOLUTIONS, interpolation=cv2.INTER_AREA)
        return frame.tobytes()

    def split_into_packets(self, data: bytes):
        """A function that splits the data into packets.

        Args:
            data (bytes): The data to split.

        Returns:
            list: A list of packets.
        """
        packets = []
        data_len = len(data)
        num_packets = data_len // PACKET_SIZE + 1

        for i in range(num_packets):
            packet = data[i * PACKET_SIZE:(i + 1) * PACKET_SIZE]
            packet_len = len(packet)
            packet_header = bytes([i, num_packets, packet_len])
            packet = packet_header + packet
            packets.append(packet)

        return packets

    def send_data(self, packets: list[bytes]):
        """A function that sends the packets to the remote destination.

        Args:
            packets (list): A list of packets to send.
        """
        for packet in packets:
            self.s.sendto(self.cipher.encrypt(packet), (self.dest_ip, self.dest_port))
            time.sleep(0.001)

class MultiSender(Sender):
    """A class that broadcasts this PC's screen to multiple remote destinations.

    Attributes:
        local_ip (str): The local IP address to bind the socket to.
        local_port (int): The local port to bind the socket to.
        dest_port (int): The port of the remote destinations.
        key (bytes): The encryption key to use for encrypting the data.
    """
    def __init__(self, local_port: int, dest_port: int, key: bytes):
        super().__init__('0.0.0.0', local_port, '255.255.255.255', dest_port, key)
        self.s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    def send_data(self, packets: list[bytes]):
        """A function that sends the packets to the remote destinations.

        Args:
            packets (list): A list of packets to send.
        """
        for packet in packets:
            self.s.sendto(self.cipher.encrypt(packet), (self.dest_ip, self.dest_port))
    
    def stop(self):
        """A function that stops the stream.
        """
        self.stream = False
        self.s.sendto(self.cipher.encrypt(b'STOP000000000000'), (self.dest_ip, self.dest_port))

class Receiver:
    def __init__(self, local_ip: str, local_port: int, key: bytes, student_mode: bool = False):
        self.local_ip = local_ip
        self.local_port = local_port
        self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.s.bind((self.local_ip, self.local_port))
        
        self.cipher = Cipher_ECB(key)
        self.lock = threading.Lock()
        
        self.student_mode = student_mode
        
    def start_stream(self):
        """This function starts the stream.
        """
        self.stream = True
        self.data = b''
        self.thread = threading.Thread(target=self.recv_frames)
        self.thread.start()
        self.show_screenshots()
    
    def recv_frame(self):
        """This function receives packets from the server.

        Args:
            s (socket): The socket to receive data from.
        """
        packets = []

        self.lock.acquire()
        first, addr = self.s.recvfrom(PACKET_SIZE)
        self.dest_addr = addr
        first = self.cipher.decrypt(first)
        if self.student_mode and first == b'STOP000000000000':
            self.stream = False
            self.lock.release()
            return
        
        data_len = int.from_bytes(first[:3], 'big')
        num_packets = int.from_bytes(first[3:5], 'big')
        packets.append(first[5:])
        
        for i in range(num_packets-1):
            packet, _ = self.s.recvfrom(PACKET_SIZE)
            packet = self.cipher.decrypt(packet)
            if self.student_mode and packet == b'STOP000000000000':
                self.stream = False
                self.lock.release()
                return
            
            packets.append(packet[5:])

        self.lock.release()

        packets = sorted(packets, key=lambda x: int.from_bytes(x[:2], 'big'))
        packets = [packet[2:] for packet in packets]
        data = b''.join(packets)
        data = data[:data_len]
        
        return data

    def show_screenshots(self):
        """This function shows the screenshot.
        """
        
        if self.student_mode:
            cv2.namedWindow('ScreenShare', cv2.WINDOW_NORMAL)
            cv2.setWindowProperty('ScreenShare', cv2.WND_PROP_FULLSCREEN, cv2.WINDOW_FULLSCREEN)
                
        state = 1
        
        while len(self.data) == 0:
            pass
        
        while self.stream:
            self.lock.acquire()
            img = cv2.imdecode(np.frombuffer(self.data, np.uint8), cv2.IMREAD_COLOR)
            if not self.student_mode:
                try:
                    state = cv2.getWindowProperty('ScreenShare', 0)
                except cv2.error as e:
                    state -= 1
                    print(state)
                    print(e)

            try:
                cv2.imshow('ScreenShare', img)
            except:
                pass
            self.lock.release()
            
            
            if state < 0:
                self.stream = False
                cv2.destroyAllWindows()
                break
            
            cv2.waitKey(1)
        
        if not self.student_mode:
            msg = b'STOP000000000000'
            self.s.sendto(self.cipher.encrypt(msg), self.dest_addr)

    def recv_frames(self):
        """This function continuously receives frames from the server.

        Args:
            s (socket): The socket to receive data from.
        """
        while self.stream:
            self.data = self.recv_frame()

import unittest
import threading
import time
from ScreenShare import MultiSender

def main():
    recv = Receiver('10.99.101.57', 25565, b'1234567890123456')
    send = MultiSender(25566, 25565, b'1234567890123456')
    threading.Thread(target=recv.start_stream).start()
    threading.Thread(target=send.start_stream).start()

if __name__ == '__main__':
    main()